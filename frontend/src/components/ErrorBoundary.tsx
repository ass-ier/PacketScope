import { Component, type ErrorInfo, type ReactNode } from 'react';

export default class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('PacketScope interface error', error.message, info.componentStack);
  }
  render() {
    if (this.state.failed) return <main className="page"><h1>The investigation view could not be displayed</h1>
      <p className="error" role="alert">An interface error occurred. Saved captures and case evidence remain on disk.</p>
      <button onClick={() => { location.hash = '/dashboard'; location.reload(); }}>Reload the workspace</button></main>;
    return this.props.children;
  }
}
