import { CONFIDENCE_COLORS, CONFIDENCE_LABELS, ENGINE_ICONS, SEARCH_PARAMETERS } from "@/types/search";
import { Search, Loader2, CheckCircle, AlertCircle, Download, Filter, X, ChevronDown, ChevronUp, ExternalLink, Copy, FileText, Shield } from "lucide-react";

interface SearchResultCardProps {
  result: SearchResult;
  index: number;
  isExpanded: boolean;
  onToggleExpand: (id: string) => void;
  onCopy: (text: string) => void;
}

export function SearchResultCard({ result, index, isExpanded, onToggleExpand, onCopy }: SearchResultCardProps) {
  const confidenceClass = CONFIDENCE_COLORS[result.confidence];
  const confidenceLabel = CONFIDENCE_LABELS[result.confidence];

  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden transition-all hover:border-gray-700">
      <div className="p-4 cursor-pointer hover:bg-gray-800/50 transition-colors" onClick={() => onToggleExpand(result.id)}>
        <div className="flex items-start gap-4">
          <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-gray-800 flex items-center justify-center text-lg">
            {ENGINE_ICONS[result.source] || "🔍"}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-medium text-white truncate">{result.title}</h4>
              <span className={`${confidenceClass} px-2 py-0.5 text-xs font-mono rounded-full`}>
                {confidenceLabel}
              </span>
              <span className="text-xs text-gray-500 px-2 py-0.5 bg-gray-800 rounded">
                {result.source.toUpperCase()}
              </span>
              <span className="text-xs text-gray-500 px-2 py-0.5 bg-gray-800 rounded">
                {SEARCH_PARAMETERS[result.parameterType].label}
              </span>
            </div>
            <p className="text-sm text-gray-400 truncate" title={result.url}>
              {result.url}
            </p>
            <p className="text-sm text-gray-500 mt-2 line-clamp-2">
              {result.snippet}
            </p>
          </div>
          <div className="flex items-center gap-1">
            <button onClick={(e) => { e.stopPropagation(); onCopy(result.url); }} className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded transition-colors" title="Copiar URL">
              <Copy className="w-4 h-4" />
            </button>
            <a href={result.url} target="_blank" rel="noopener noreferrer" className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded transition-colors" title="Abrir en nueva pestaña">
              <ExternalLink className="w-4 h-4" />
            </a>
            <button onClick={(e) => { e.stopPropagation(); onToggleExpand(result.id); }} className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded transition-colors" title={isExpanded ? "Colapsar" : "Expandir"}>
              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </div>

      {isExpanded && (
        <div className="border-t border-gray-800 bg-gray-950/50 p-4 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
            <div>
              <span className="text-gray-500">ID:</span>
              <code className="text-gray-300 font-mono ml-2 break-all">{result.id}</code>
            </div>
            <div>
              <span className="text-gray-500">Timestamp:</span>
              <span className="text-gray-300 ml-2">{new Date(result.timestamp).toLocaleString()}</span>
            </div>
            <div>
              <span className="text-gray-500">Parámetro:</span>
              <span className="text-gray-300 ml-2">{SEARCH_PARAMETERS[result.parameterType].label}</span>
            </div>
            <div>
              <span className="text-gray-500">Valor buscado:</span>
              <code className="text-gray-300 font-mono ml-2">{result.matchedValue}</code>
            </div>
            <div className="sm:col-span-2">
              <span className="text-gray-500">URL completa:</span>
              <div className="mt-1 p-2 bg-gray-800 rounded text-xs text-gray-300 break-all font-mono">
                {result.url}
              </div>
            </div>
            {result.metadata && Object.keys(result.metadata).length > 0 && (
              <div className="sm:col-span-2">
                <span className="text-gray-500">Metadatos:</span>
                <pre className="mt-1 p-2 bg-gray-800 rounded text-xs text-gray-300 overflow-auto max-h-40">
                  {JSON.stringify(result.metadata, null, 2)}
                </pre>
              </div>
            )}
          </div>
          <div className="flex gap-2 pt-2 border-t border-gray-800">
            <button onClick={(e) => { e.stopPropagation(); onCopy(result.url); }} className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors">
              <Copy className="w-3.5 h-3.5" />
              Copiar URL
            </button>
            <a href={result.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm transition-colors">
              <ExternalLink className="w-3.5 h-3.5" />
              Abrir enlace
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
