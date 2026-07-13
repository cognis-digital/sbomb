// polyglot/typescript/filesystem_traversal.ts

import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';

/**
 * Configuration options for filesystem traversal.
 */
export interface TraverseOptions {
  rootPath: string;
  recursive?: boolean;
  maxDepth?: number;
  followSymlinks?: boolean;
  filterExtensions?: string[];
  minFileSize?: number;
  maxFileSize?: number;
  includeHidden?: boolean;
  parallelLimit?: number;
}

/**
 * Metadata for a single file discovered during traversal.
 */
export interface FileMetadata {
  path: string;
  relativePath: string;
  size: number;
  mode: string;
  mtime: Date;
  atime: Date;
  ctime: Date;
  isSymlink?: boolean;
  target?: string;
}

/**
 * Metadata for a directory discovered during traversal.
 */
export interface DirectoryMetadata {
  path: string;
  relativePath: string;
  entryTime: Date;
  exitTime: Date;
  fileCount: number;
  totalSize: number;
  subdirectoryCount: number;
}

/**
 * Result of a complete filesystem traversal.
 */
export interface TraverseResult {
  files: FileMetadata[];
  directories: DirectoryMetadata[];
  rootPath: string;
  startTime: Date;
  endTime: Date;
  totalFiles: number;
  totalDirectories: number;
  totalSize: number;
}

/**
 * Event types emitted during traversal.
 */
export interface TraverseEvents {
  'file:discover': (path: string, metadata: FileMetadata) => void;
  'directory:enter': (path: string, metadata: DirectoryMetadata) => void;
  'directory:exit': (path: string, metadata: DirectoryMetadata) => void;
  'progress': (current: number, total: number) => void;
  'error': (error: Error, path?: string) => void;
}

/**
 * Options for the traversal event emitter.
 */
export interface EventOptions {
  maxListeners?: number;
  once?: boolean;
}

/**
 * A class that handles filesystem traversal with event emission and progress tracking.
 */
export class FilesystemTraverser implements TraverseEvents {
  private rootPath: string;
  private options: TraverseOptions;
  private events: Partial<TraverseEvents> = {};
  private fileBuffer: FileMetadata[] = [];
  private directoryBuffer: DirectoryMetadata[] = [];
  private currentDirectory: DirectoryMetadata | null = null;
  private totalFiles: number = 0;
  private totalDirectories: number = 0;
  private startTime: Date;

  constructor(options: TraverseOptions, eventOptions?: EventOptions) {
    this.rootPath = path.resolve(options.rootPath);
    this.options = {
      recursive: true,
      maxDepth: Infinity,
      followSymlinks: false,
      filterExtensions: [],
      minFileSize: 0,
      maxFileSize: Infinity,
      includeHidden: true,
      parallelLimit: 1,
      ...options,
    };

    this.startTime = new Date();
    this.setMaxListeners(eventOptions?.maxListeners || 256);
  }

  /**
   * Register an event handler.
   */
  on<T extends keyof TraverseEvents>(event: T, listener: TraverseEvents[T]): void {
    if (this.events[event]) {
      this.events[event] = [...(Array.isArray(this.events[event]) ? this.events[event] : []), listener];
    } else {
      this.events[event] = [listener];
    }
  }

  /**
   * Register a one-time event handler.
   */
  once<T extends keyof TraverseEvents>(event: T, listener: TraverseEvents[T]): void {
    const wrappedListener = (...args: any[]) => {
      this.off(event, listener);
      listener(...args);
    };
    this.on(event, wrappedListener);
  }

  /**
   * Remove an event handler.
   */
  off<T extends keyof TraverseEvents>(event: T, listener?: TraverseEvents[T]): void {
    if (!this.events[event]) return;
    
    const handlers = Array.isArray(this.events[event]) ? this.events[event] : [this.events[event]];
    const index = handlers.indexOf(listener);
    if (index !== -1) {
      this.events[event].splice(index, 1);
    }
  }

  /**
   * Emit an event.
   */
  emit<T extends keyof TraverseEvents>(event: T, ...args: any[]): boolean | undefined {
    const handlers = Array.isArray(this.events[event]) ? this.events[event] : [this.events[event]];
    
    for (const handler of handlers) {
      if (handler && typeof handler === 'function') {
        try {
          handler(...args);
        } catch (error) {
          console.error(`Event '${event}' handler threw an error:`, error);
        }
      }
    }
    
    return true;
  }

  /**
   * Check if a file should be filtered out.
   */
  private shouldFilterFile(fileMetadata: FileMetadata): boolean {
    // Filter by size
    if (fileMetadata.size < this.options.minFileSize) {
      return true;
    }
    if (fileMetadata.size > this.options.maxFileSize) {
      return true;
    }

    // Filter by extension
    if (!this.options.filterExtensions.length) {
      return false;
    }

    const ext = path.extname(fileMetadata.path).toLowerCase();
    return !this.options.filterExtensions.some(
      e => e.toLowerCase() === ext || e.endsWith('/*') && ext.startsWith(e.slice(0, -1))
    );
  }

  /**
   * Check if a file is hidden.
   */
  private isHidden(fileMetadata: FileMetadata): boolean {
    const name = path.basename(fileMetadata.path);
    return !this.options.includeHidden && (name.startsWith('.') || name === 'lost+found');
  }

  /**
   * Process a single directory entry.
   */
  private async processEntry(
    dirPath: string,
    relPath: string,
    isDirectory: boolean,
    parentDir: DirectoryMetadata | null = null
  ): Promise<void> {
    const currentDepth = this.getDepth(relPath);

    if (currentDepth > this.options.maxDepth) {
      return;
    }

    try {
      const stats = await fs.promises.stat(dirPath, { bigint: true });
      
      // Handle symlinks
      let isSymlink = false;
      let target: string | undefined;
      
      if (stats.isSymbolicLink()) {
        isSymlink = true;
        try {
          const resolved = await fs.promises.readlink(dirPath);
          target = resolved;
          
          if (this.options.followSymlinks && !isDirectory) {
            // Follow symlink to file
            await this.processEntry(resolved, relPath, false, parentDir);
            return;
          } else if (this.options.followSymlinks && isDirectory) {
            // Follow symlink to directory
            const resolvedStats = await fs.promises.stat(resolved);
            await this.processEntry(resolved, relPath, true, parentDir);
            return;
          }
        } catch {
          // readlink failed, treat as regular file/directory
        }
      }

      if (isDirectory) {
        const dirMetadata: DirectoryMetadata = {
          path: dirPath,
          relativePath: relPath,
          entryTime: new Date(),
          exitTime: new Date(),
          fileCount: 0,
          totalSize: 0,
          subdirectoryCount: 0,
        };

        this.currentDirectory = dirMetadata;
        this.directoryBuffer.push(dirMetadata);
        this.totalDirectories++;

        // Emit directory enter event
        if (this.events['directory:enter']) {
          this.emit('directory:enter', dirPath, dirMetadata);
        }

        const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
        
        for (const entry of entries) {
          const childPath = path.join(dirPath, entry.name);
          const childRelPath = relPath ? path.join(relPath, entry.name) : entry.name;

          if (!this.isHidden({ path: childPath, relativePath: childRelPath, size: 0, mode: '', mtime: new Date(), atime: new Date(), ctime: new Date() })) {
            await this.processEntry(childPath, childRelPath, entry.isDirectory(), dirMetadata);
          }
        }

        // Calculate final directory stats
        if (this.currentDirectory) {
          const exitTime = new Date();
          this.currentDirectory.exitTime = exitTime;
          
          for (const file of this.fileBuffer) {
            if (file.relativePath.startsWith(relPath + '/') || file.relativePath === relPath) {
              this.currentDirectory.totalSize += file.size;
              this.currentDirectory.fileCount++;
            }
          }

          // Count subdirectories
          const dirCount = this.directoryBuffer.filter(
            d => d.path !== dirMetadata.path && 
                   (d.path.startsWith(dirMetadata.path + '/') || d.path === dirMetadata.path)
          ).length;
          
          this.currentDirectory.subdirectoryCount = dirCount;

          // Emit directory exit event
          if (this.events['directory:exit']) {
            this.emit('directory:exit', dirPath, this.currentDirectory);
          }

          this.currentDirectory = null;
        }
      } else {
        const fileMetadata: FileMetadata = {
          path: dirPath,
          relativePath: relPath,
          size: stats.size,
          mode: stats.mode.toString(8),
          mtime: new Date(stats.mtimeMs),
          atime: new Date(stats.atimeMs),
          ctime: new Date(stats.ctimeMs),
          isSymlink,
          target,
        };

        if (!this.shouldFilterFile(fileMetadata)) {
          this.fileBuffer.push(fileMetadata);
          this.totalFiles++;

          // Emit file discover event
          if (this.events['file:discover']) {
            this.emit('file:discover', dirPath, fileMetadata);
          }
        }
      }

    } catch (error) as any {
      const err = error instanceof Error ? error : new Error(String(error));
      
      // Emit error event if registered
      if (this.events['error']) {
        this.emit('error', err, dirPath);
      } else {
        console.error(`Error processing ${dirPath}:`, err.message);
      }

      // Continue despite errors to avoid stopping traversal
    }
  }

  /**
   * Calculate the depth of a path relative to root.
   */
  private getDepth(relPath: string): number {
    if (!relPath) return 0;
    const parts = relPath.split('/').filter(p => p);
    return parts.length - 1;
  }

  /**
   * Perform the actual traversal.
   */
  async traverse(): Promise<TraverseResult> {
    this.fileBuffer = [];
    this.directoryBuffer = [];
    this.totalFiles = 0;
    this.totalDirectories = 0;
    this.currentDirectory = null;

    // Emit start event if registered
    if (this.events['progress']) {
      this.emit('progress', 0, 1);
    }

    await this.processEntry(this.rootPath, '', true);

    // Calculate totals
    const totalSize = this.fileBuffer.reduce((sum, f) => sum + f.size, 0);

    // Emit final progress
    if (this.events['progress']) {
      this.emit('progress', this.totalFiles + this.totalDirectories, this.totalFiles + this.totalDirectories);
    }

    const result: TraverseResult = {
      files: [...this.fileBuffer],
      directories: [...this.directoryBuffer],
      rootPath: this.rootPath,
      startTime: this.startTime,
      endTime: new Date(),
      totalFiles: this.totalFiles,
      totalDirectories: this.totalDirectories,
      totalSize,
    };

    return result;
  }

  /**
   * Get a progress report.
   */
  getProgress(): { filesProcessed: number; directoriesProcessed: number; totalSize: number } {
    const currentTotal = this.fileBuffer.length + this.directoryBuffer.length;
    return {
      filesProcessed: this.totalFiles,
      directoriesProcessed: this.totalDirectories,
      totalSize: this.fileBuffer.reduce((sum, f) => sum + f.size, 0),
    };
  }

  /**
   * Clear buffers and reset state.
   */
  clear(): void {
    this.fileBuffer = [];
    this.directoryBuffer = [];
    this.currentDirectory = null;
    this.totalFiles = 0;
    this.totalDirectories = 0;
  }
}

/**
 * A convenience class that wraps FilesystemTraverser and provides SBOM-specific utilities.
 */
export class SbomFilesystemTraverser extends FilesystemTraverser {
  private sbomComponents: any[] = [];
  private kernelModules: Map<string, string> = new Map();

  constructor(options: TraverseOptions) {
    super(options);
    
    // Register default handlers for SBOM-specific processing
    this.on('file:discover', (filePath: string, metadata: FileMetadata) => {
      this.processSbomFile(filePath, metadata);
    });

    this.on('directory:enter', (dirPath: string, dirMeta: DirectoryMetadata) => {
      if (this.isKernelDirectory(dirPath)) {
        this.processKernelDirectory(dirPath, dirMeta);
      }
    });

    this.on('progress', (current: number, total: number) => {
      console.log(`\r[SBOM Traverse] Progress: ${((current / total) * 100).toFixed(2)}%`);
    });
  }

  /**
   * Process a discovered file for SBOM component detection.
   */
  private processSbomFile(filePath: string, metadata: FileMetadata): void {
    // Detect binary executables
    if (this.isExecutable(metadata)) {
      this.detectBinaryComponent(filePath, metadata);
    }

    // Detect shared libraries
    else if (metadata.path.endsWith('.so') || metadata.path.includes('/lib/') || 
             metadata.path.includes('/usr/lib/')) {
      this.detectLibraryComponent(filePath, metadata);
    }

    // Detect package manifests
    else if (this.isPackageManifest(metadata)) {
      this.processPackageManifest(filePath, metadata);
    }

    // Detect kernel modules
    else if (metadata.path.endsWith('.ko') || metadata.path.includes('/lib/modules/')) {
      const moduleName = path.basename(path.dirname(filePath));
      this.kernelModules.set(moduleName, metadata.path);
    }
  }

  /**
   * Check if a file is likely an executable binary.
   */
  private isExecutable(metadata: FileMetadata): boolean {
    // Check by extension
    const ext = path.extname(metadata.path).toLowerCase();
    if (['.elf', '.bin', '.exe'].includes(ext)) return true;

    // Check by common paths
    const name = path.basename(metadata.path);
    if (name.startsWith('vmlinuz') || name.startsWith('Image')) return true;

    // Check by magic bytes for ELF files
    try {
      const header = fs.readFileSync(metadata.path, 64);
      if (header[0] === 0x7f && header[1] === 'E' && header[2] === 'L' && header[3] === 'F') {
        return true;
      }
    } catch {
      // Not readable, skip magic check
    }

    return false;
  }

  /**
   * Check if a file is likely a shared library.
   */
  private isLibrary(metadata: FileMetadata): boolean {
    const ext = path.extname(metadata.path).toLowerCase();
    return