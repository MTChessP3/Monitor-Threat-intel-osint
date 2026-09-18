'use client';

import React, { useCallback, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, FileText, X, FileSpreadsheet, FileJson, FileCode, CheckCircle, AlertCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Card, CardContent } from '@/components/ui/card';
import { sha256File } from '@/lib/takedown/hashGenerator';
import { defangUrl, normalizeUrl, isValidUrl } from '@/lib/takedown/defang';
import { parseFile } from '@/lib/takedown/fileParser';

interface ParsedFileData {
  validUrls: string[];
  invalidUrls: string[];
  fileHash: string;
  fileName: string;
  fileType: string;
  totalLines: number;
}

interface DragDropUploadProps {
  onFileProcessed: (data: ParsedFileData) => void;
  disabled?: boolean;
}

export function DragDropUpload({ onFileProcessed, disabled }: DragDropUploadProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [parsedData, setParsedData] = useState<ParsedFileData | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback(async (file: File) => {
    const validExtensions = ['.txt', '.csv', '.xlsx'];
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!validExtensions.includes(ext)) {
      return;
    }

    setProcessing(true);
    setProgress(10);

    try {
      const buffer = await file.arrayBuffer();
      setProgress(30);

      const result = await parseFile(Buffer.from(buffer), file.name);
      setProgress(70);

      const fileHash = sha256File(Buffer.from(buffer));

      const parsedData: ParsedFileData = {
        validUrls: result.validUrls,
        invalidUrls: result.invalidUrls,
        fileHash,
        fileName: file.name,
        fileType: ext,
        totalLines: result.totalLines,
      };

      setParsedData(parsedData);
      setProgress(100);
      onFileProcessed(parsedData);
    } catch (error) {
      console.error('File processing error:', error);
    } finally {
      setProcessing(false);
      setProgress(0);
    }
  }, [onFileProcessed]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      processFile(files[0]);
    }
  }, [processFile]);

  const getIcon = (fileType: string) => {
    switch (fileType) {
      case '.txt': return <FileText className="w-4 h-4" />;
      case '.csv': return <FileSpreadsheet className="w-4 h-4" />;
      case '.xlsx': return <FileCode className="w-4 h-4" />;
      default: return <FileText className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-4">
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-300 ${
          isDragOver
            ? 'border-green-500 bg-green-500/10 scale-[1.02]'
            : 'border-gray-600 hover:border-gray-500 hover:bg-gray-800/50'
        } ${disabled ? 'opacity-50 pointer-events-none' : ''}`}
        onClick={() => !disabled && !processing && fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".txt,.csv,.xlsx"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) processFile(file);
          }}
          className="hidden"
          disabled={disabled || processing}
        />

        <AnimatePresence mode="wait">
          {processing ? (
            <motion.div key="processing" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <div className="flex flex-col items-center gap-4">
                <div className="w-16 h-16 border-4 border-primary/20 border-t-primary rounded-full animate-spin" />
                <div>
                  <p className="font-medium">Procesando archivo...</p>
                  <Progress value={progress} className="h-2 w-64 mt-2" />
                  <p className="text-xs text-muted-foreground mt-2">{progress}% - Calculando SHA-256</p>
                </div>
              </div>
            </motion.div>
          ) : parsedData ? (
            <motion.div key="success" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <div className="flex flex-col items-center gap-4">
                <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center text-green-500">
                  <CheckCircle className="w-8 h-8" />
                </div>
                <div>
                  <p className="font-semibold">{parsedData.fileName}</p>
                  <div className="flex items-center gap-2 mt-2">
                    <Badge variant="secondary">{parsedData.validUrls.length} URLs válidas</Badge>
                    <Badge variant="outline">{parsedData.invalidUrls.length} inválidas</Badge>
                    <Badge variant="outline" className="font-mono text-xs">
                      SHA-256: {parsedData.fileHash?.substring(0, 16)}...
                    </Badge>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-sm text-muted-foreground">
                  <span>{getIcon(parsedData.fileType)} {parsedData.fileType}</span>
                  <span>{parsedData.totalLines} líneas</span>
                </div>
              </div>
            </motion.div>
          ) : (
            <motion.div key="upload" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <div className="flex flex-col items-center gap-4">
                <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center text-primary">
                  <Upload className="w-8 h-8" />
                </div>
                <div>
                  <p className="font-semibold mb-1">Arrastre y suelte aquí</p>
                  <p className="text-sm text-muted-foreground">.txt, .csv, .xlsx (máx. 10MB)</p>
                  <p className="text-xs text-muted-foreground mt-1">Se calculará automáticamente el hash SHA-256</p>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
