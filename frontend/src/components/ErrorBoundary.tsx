import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error caught by ErrorBoundary:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }
      return (
        <div style={{ padding: 24, maxWidth: 640, margin: '40px auto' }}>
          <div className="card" style={{ padding: 24, border: '1px solid var(--border-danger, #ef4444)' }}>
            <div className="flex items-center gap-12 mb-12">
              <span style={{ fontSize: 24, color: '#ef4444' }}>⚠</span>
              <h2 style={{ fontSize: 18, margin: 0 }}>Application encountered an error</h2>
            </div>
            <p className="text-sm text-muted mb-16">
              A component error occurred while rendering. You can reload the application to reset state.
            </p>
            <pre className="code-block mb-16" style={{ whiteSpace: 'pre-wrap', color: '#ef4444', fontSize: 12 }}>
              {this.state.error?.message || 'Unknown error'}
            </pre>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.reload();
              }}
            >
              ⟳ Reload Application
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
