import type { SlideContentProfile, LayoutScore } from './layoutScoring.types';

export interface PresentationContext {
  title?: string;
  purpose?: string;
  audience?: string;
  industry?: string;
  tone?: string;
  slideNumber: number;
  totalSlides: number;
  previousSlides?: {
    slideNumber: number;
    purpose?: string;
    layoutId?: string;
  }[];
  nextSlide?: {
    purpose?: string;
  };
}

export interface SlideCopy {
  title?: string;
  subtitle?: string;
  body?: string;
}

export interface AILayoutSelection {
  selectedLayoutId: string;
  confidence: number;
  reason: string;
  alternativeLayoutId?: string;
}

export type LayoutAiSelectionSource =
  | 'ai'
  | 'deterministic'
  | 'single_candidate'
  | 'fallback';

export interface LayoutAiSelectionResult extends AILayoutSelection {
  source: LayoutAiSelectionSource;
  usedFallback: boolean;
}

export interface CompactLayoutCandidate {
  layoutId: string;
  score: number;
  breakdown: LayoutScore['breakdown'];
  reasons?: string[];
  layout: {
    name?: string;
    category?: string;
    slidePurposes?: string[];
    contentTypes?: string[];
    composition?: {
      structure?: string;
      visualWeight?: string;
      imagePosition?: string;
      textPosition?: string;
    };
    contentCapacity?: { density?: string };
    supportedElements?: Record<string, boolean>;
    style?: {
      designStyles?: string[];
      moods?: string[];
      industries?: string[];
    };
  };
}

export interface SelectBestLayoutWithAIInput {
  slide: SlideContentProfile;
  candidates: LayoutScore[];
  presentationContext?: PresentationContext;
  theme?: { name?: string; tone?: string } | Record<string, unknown> | null;
  previousLayoutIds?: string[];
  layoutsById?: Record<string, unknown>;
  slideCopy?: SlideCopy;
  debug?: boolean;
  chatJson?: (opts: object) => Promise<{ data: object }>;
  config?: Record<string, unknown>;
}
