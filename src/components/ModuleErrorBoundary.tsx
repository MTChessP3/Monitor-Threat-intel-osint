'use client';

import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: React.ReactNode;
  module?: string;
}

interface State {
  hasError: boolean;
}

export default class ModuleErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: unknown) {
    console.error(`[ModuleErrorBoundary] ${this.props.module || 'módulo'} falló al renderizar:`, error);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="bg-gray-900 border border-red-500/40 rounded-xl p-10 text-center space-y-4">
          <AlertTriangle className="w-12 h-12 mx-auto text-red-400" />
          <h3 className="text-lg font-semibold">Error al renderizar {this.props.module || 'el módulo'}</h3>
          <p className="text-gray-400 max-w-md mx-auto text-sm">
            Se produjo un error inesperado al mostrar este módulo. Reinicia el módulo para continuar; tus demás datos no se ven afectados.
          </p>
          <div className="flex flex-wrap gap-2 justify-center">
            <button
              onClick={() => { this.setState({ hasError: false }); }}
              className="px-4 py-2 bg-teal-600 hover:bg-teal-700 rounded-lg text-sm font-medium flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" /> Reiniciar módulo
            </button>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm font-medium"
            >
              Recargar página
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}