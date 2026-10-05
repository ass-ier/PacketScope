import logging
from contextlib import asynccontextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.routes import router
from app.core.config import Settings
from app.core.db import make_database
from app.core.safety import LocalSafetyMiddleware
from app.services.analysis import JobRunner
from app.services.detection import seed_rules
from app.services.attack import seed_attack

log = logging.getLogger("packetscope")


def create_app(settings: Settings | None = None):
    settings = settings or Settings()
    settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    engine, database = make_database(settings.data_dir / "packetscope.sqlite")

    @asynccontextmanager
    async def lifespan(app):
        config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
        config.set_main_option("script_location", str(Path(__file__).parents[1] / "migrations"))
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        with database() as db:
            seed_rules(db)
            seed_attack(db)
        app.state.jobs = JobRunner(database, settings)
        try:
            yield
        finally:
            app.state.jobs.close()
            engine.dispose()

    app = FastAPI(title="PacketScope", version="1.0.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.database = database
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))

    app.add_middleware(LocalSafetyMiddleware, settings=settings)
    app.include_router(router)
    dist = Path(__file__).parents[2] / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="frontend")
    return app


app = create_app()
