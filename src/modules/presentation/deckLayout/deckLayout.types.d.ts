/**
 * Semantic layout metadata for AI layout selection.
 * Wraps existing DECK_LAYOUT v2 slot schemas; does not replace them.
 */

export type CanvasElementType =
  | 'text'
  | 'image'
  | 'shape'
  | 'icon'
  | 'chart'
  | 'table'
  | 'embed';

export interface CanvasPlacement {
  x: number;
  y: number;
  width: number;
  height: number;
  rotation?: number;
  opacity?: number;
}

/** Runtime PPT canvas element (Joi / editor contract). */
export interface CanvasElement {
  id: string;
  type: CanvasElementType;
  role?: string | null;
  layer?: number;
  slotId?: string;
  presetId?: string;
  placement: CanvasPlacement;
  content?: Record<string, unknown>;
  [key: string]: unknown;
}

export type DeckLayoutCategory =
  | 'hero'
  | 'title'
  | 'section'
  | 'content'
  | 'image'
  | 'data'
  | 'comparison'
  | 'process'
  | 'timeline'
  | 'quote'
  | 'team'
  | 'product'
  | 'pricing'
  | 'closing'
  | 'chart'
  | 'table';

export type DeckLayoutSlidePurpose =
  | 'cover'
  | 'introduction'
  | 'problem'
  | 'solution'
  | 'market'
  | 'product'
  | 'features'
  | 'benefits'
  | 'statistics'
  | 'traction'
  | 'business-model'
  | 'competition'
  | 'process'
  | 'roadmap'
  | 'team'
  | 'pricing'
  | 'conclusion';

/** Semantic capabilities of a layout (not the same as catalog content_type). */
export type DeckLayoutContentCapability =
  | 'title'
  | 'subtitle'
  | 'paragraph'
  | 'bullets'
  | 'image'
  | 'icon'
  | 'statistic'
  | 'metrics'
  | 'cards'
  | 'chart'
  | 'table'
  | 'timeline'
  | 'quote'
  | 'comparison';

export type DeckLayoutDensity = 'low' | 'medium' | 'high';

export type DeckLayoutStructure =
  | 'centered'
  | 'split'
  | 'two-column'
  | 'three-column'
  | 'grid'
  | 'full-image'
  | 'text-heavy'
  | 'image-heavy'
  | 'card-grid';

export type DeckLayoutVisualWeight = 'text-heavy' | 'image-heavy' | 'balanced' | 'data-heavy';

export type DeckLayoutImagePosition =
  | 'none'
  | 'left'
  | 'right'
  | 'top'
  | 'bottom'
  | 'center'
  | 'full';

export type DeckLayoutTextPosition = 'left' | 'right' | 'top' | 'bottom' | 'center';

export type DeckLayoutAlignment = 'left' | 'center' | 'right';

export type DeckLayoutDesignStyle =
  | 'minimal'
  | 'modern'
  | 'editorial'
  | 'corporate'
  | 'luxury'
  | 'playful'
  | 'bold'
  | 'clean'
  | 'premium';

export type DeckLayoutMood =
  | 'professional'
  | 'premium'
  | 'energetic'
  | 'calm'
  | 'futuristic'
  | 'trustworthy'
  | 'creative'
  | 'confident';

export interface DeckLayoutContentCapacity {
  maxTitleCharacters: number;
  maxSubtitleCharacters: number;
  maxBodyCharacters: number;
  maxBullets: number;
  maxCards: number;
  maxImages: number;
  maxMetrics: number;
  maxColumns: number;
  density: DeckLayoutDensity;
}

export interface DeckLayoutComposition {
  structure: DeckLayoutStructure;
  imagePosition: DeckLayoutImagePosition;
  textPosition: DeckLayoutTextPosition;
  alignment: DeckLayoutAlignment;
  visualWeight: DeckLayoutVisualWeight;
}

export interface DeckLayoutStyle {
  designStyles: DeckLayoutDesignStyle[];
  moods: DeckLayoutMood[];
  industries: string[];
}

export interface DeckLayoutSupportedElements {
  title: boolean;
  subtitle: boolean;
  body: boolean;
  bullets: boolean;
  image: boolean;
  icons: boolean;
  metrics: boolean;
  chart: boolean;
  table: boolean;
  cards: boolean;
  quote: boolean;
}

/** Existing DECK_LAYOUT v2 slot schema (authoring source of truth). */
export interface DeckLayoutSchema {
  layout_id: string;
  content_type: string;
  schemaVersion?: number;
  grid?: string;
  shapePolicy?: string;
  slots: Array<{
    id: string;
    region: string;
    role: string;
    placeholder_text?: string | null;
    layer?: number;
    [key: string]: unknown;
  }>;
  preview?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface DeckLayout {
  id: string;
  name: string;
  description: string;
  version: number;
  category: DeckLayoutCategory;
  slidePurposes: DeckLayoutSlidePurpose[];
  contentTypes: DeckLayoutContentCapability[];
  tags: string[];
  /** Existing catalog taxonomy: title, image+text, chart, … */
  contentType: string;
  contentCapacity: DeckLayoutContentCapacity;
  composition: DeckLayoutComposition;
  style: DeckLayoutStyle;
  supportedElements: DeckLayoutSupportedElements;
  schema: DeckLayoutSchema;
  elements: CanvasElement[];
  extensions?: Record<string, unknown>;
}

export interface DeckLayoutValidationResult {
  ok: boolean;
  errors: string[];
}
