import type { DeckLayoutDensity } from './deckLayout.types';

export interface SlideContentProfile {
  slideNumber?: number;
  purpose: string;
  contentTypes: string[];
  titleLength: number;
  subtitleLength: number;
  bodyLength: number;
  bulletCount: number;
  cardCount: number;
  imageCount: number;
  metricCount: number;
  columnCount?: number;
  hasChart: boolean;
  hasTable: boolean;
  hasQuote: boolean;
  density: DeckLayoutDensity;
  preferredStyles?: string[];
  preferredMoods?: string[];
  industry?: string;
}

export interface LayoutScoringWeights {
  purposeMatch: number;
  contentTypeMatch: number;
  capacityMatch: number;
  compositionMatch: number;
  styleMatch: number;
  industryMatch: number;
}

export interface LayoutScoreBreakdown {
  purposeMatch: number;
  contentTypeMatch: number;
  capacityMatch: number;
  compositionMatch: number;
  styleMatch: number;
  industryMatch: number;
  repetitionPenalty: number;
}

export type LayoutScoreConfidence = 'excellent' | 'strong' | 'good' | 'acceptable' | 'weak';

export interface LayoutScore {
  layoutId: string;
  score: number;
  confidence: LayoutScoreConfidence;
  breakdown: LayoutScoreBreakdown;
  reasons: string[];
  warnings: string[];
}

export interface LayoutRankingOptions {
  previousLayoutIds?: string[];
  topN?: number;
  debug?: boolean;
  weights?: Partial<LayoutScoringWeights>;
}

export type CompatibilityStatus = 'hardReject' | 'ok';

export interface CompatibilityPenalty {
  kind: 'softPenalty';
  field: string;
  message: string;
}

export interface CompatibilityResult {
  status: CompatibilityStatus;
  reasons: string[];
  penalties: CompatibilityPenalty[];
}

export interface ScoreLayoutOptions {
  previousLayoutIds?: string[];
  weights?: Partial<LayoutScoringWeights>;
  debug?: boolean;
}
