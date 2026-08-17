# AI image gen — infographic issues

Original QA findings below. **Backend status (OpenAI-only infographic pipeline):**

| Issue | Status |
|---|---|
| #1 Text corruption | Addressed: quoted `exactText`, vision QA, one free in-place edit. Residual: model can still garble after one retry — flagged on `infographicQuality`. |
| #2 Number sequence | Addressed: planner emits `01..N`, dual badge+heading, QA + edit. |
| #3 Statistical logic | Addressed: funnel metrics pre-check (must decrease) + QA `illogicalData`. |
| #4 Date/year | Addressed: 4-digit years in spec/QA (`yearErrors`). |
| #5 Missing / clipped | Addressed: completeness vs `expectedStepCount`; infographic **contain-crop** (not social cover). |
| #6 Flow logic | Addressed: per-layout prompt (LTR, no loops; comparison aligned). |
| #7 Complex shapes | Addressed: hierarchy/funnel as stacked rectangles, not morphing geometry. |
| #8–#12 Polish | Addressed in typesetting prompt (equal cards, no overlap, type hierarchy, discrete colors). |
| FLUX / other vendors | Out of scope (OpenAI only). |
| SVG text overlay | Out of scope. |
| Forced HD/landscape | Not forced. **Default** for infographic is HD + landscape; picker can override. |

Silent QA edit is included in the original generate/regenerate charge (no extra AC). Defaults: `gpt-image-1-hd` + `landscape` when omitted.

---

## 🔴 CRITICAL ISSUES (Blockers)

### 1. Text Rendering Corruption
**Affects**: All content types  
**Severity**: CRITICAL - Makes outputs unusable

**Problem**: Text is garbled, misspelled, or completely nonsensical
- Words merged: "Manudlresearch" → "Manual research"
- Letters scrambled: "irzelligent" → "intelligent"
- Complete gibberish: "Thausee pronides a prompli-reoveired afno"
- Character encoding fails: "Kоgаveаи" → "Kasparov"

**Impact**: Every generated infographic has unprofessional, unreadable text

**Exception**: Large display numbers/stats render MUCH better (88%, 1000, 4.4T are mostly accurate)

**Backend Action Required**:
- Test different models for text accuracy (FLUX-pro, FLUX-dev, SD 3.5)
- Implement post-generation text validation/correction layer
- Consider text overlay feature (generate image, add text separately)
- Add user warnings about text accuracy limitations

---

### 2. Number Sequence Corruption
**Affects**: Process infographics, Timelines, Funnels  
**Severity**: CRITICAL - Breaks logical flow

**Problem**: Sequential numbering fails completely
- Missing numbers: Shows 01, 02, 05 (missing 03, 04)
- Wrong sequence: 01, 02, 08, 04, 05, 06 (08 instead of 03!)
- Duplicates: 01, 02, 5, 4, 5 (duplicate 5)
- Random symbols: Dollar sign "$" instead of number

**Examples**:
- **Process infographic**: Only 5 steps shown instead of 6
- **Timeline**: "150" instead of "1950" (number truncation)
- **Funnel**: Shows "08" in middle of 01-06 sequence

**Backend Action Required**:
- Add sequence validation (reject outputs with wrong numbering)
- Test alternative labels (A-F, Stage 1-6, spelled-out numbers)
- Implement post-processing to fix/flag sequence errors

---

### 3. Statistical Logic Failures
**Affects**: Funnels, Data visualizations  
**Severity**: CRITICAL - Creates impossible data

**Problem**: Numbers don't follow logical relationships
- Funnel metrics increase mid-flow: 150 → 600 → 450 (should always decrease)
- Model treats numbers as decorative, not related data
- No validation of data relationships

**Impact**: Generated infographics show impossible statistics

**Backend Action Required**:
- Implement numeric validation layer
- Check data relationships (funnels must decrease, timelines must be chronological)
- Add explicit validation rules in prompts
- Flag/reject outputs with illogical data

---

## 🟠 MAJOR ISSUES (Significant Quality Problems)

### 4. Date/Year Errors
**Affects**: Timelines  
**Severity**: MAJOR - Historical inaccuracy

**Problem**: 4-digit years are corrupted or wrong
- "150" instead of "1950"
- "1857" when prompt specified "1997"

**Backend Action Required**:
- Add year range validation (1900-2026)
- Test spelled-out years ("nineteen fifty")
- Validate dates against expected ranges

---

### 5. Missing Content Elements
**Affects**: Process infographics  
**Severity**: MAJOR - Incomplete output

**Problem**: Requested elements are missing
- Asked for 6 steps, only 5 rendered
- Missing final step entirely
- Content cut off at bottom of canvas

**Backend Action Required**:
- Add completeness validation (count elements)
- Add canvas framing instructions (5% margin)
- Flag incomplete outputs

---

### 6. Flow Logic Broken
**Affects**: Process flows, Comparisons  
**Severity**: MAJOR - Confusing structure

**Problem**: Arrows and connections don't make sense
- Arrows loop back incorrectly
- No clear linear progression
- Comparison columns don't align horizontally

**Backend Action Required**:
- Add explicit flow direction instructions
- For comparisons: specify horizontal alignment
- Consider template-based layouts

---

### 7. Complex Shape Failures
**Affects**: Pyramids, Funnels  
**Severity**: MAJOR - Visual metaphor broken

**Problem**: Progressive shape morphing fails
- Pyramid starts correct but becomes rectangles
- Funnel narrowing is inconsistent
- Can't maintain geometric relationships

**Backend Action Required**:
- Avoid complex shapes in prompts
- Use simpler alternatives (stacked rectangles + visual cues)
- Add template-based generation for structured layouts

---

## 🟡 MODERATE ISSUES (Polish Problems)

### 8. Grid Layout Inconsistency
**Affects**: Stats grids  
**Problem**: Uneven card sizes in grids (requested 2x3, got irregular layout)

### 9. Icon-Text Integration
**Affects**: All infographics  
**Problem**: Inconsistent icon sizing/placement, some overlap text

### 10. Visual Hierarchy Weak
**Affects**: Process flows  
**Problem**: Steps blend together, no clear distinction between cards

### 11. Typography Generic
**Affects**: All types  
**Problem**: Doesn't match "premium SaaS" aesthetic requested

### 12. Color Gradients Inconsistent
**Affects**: Hierarchies, Funnels  
**Problem**: Gradient progression not smooth, some levels same color

---

## ✅ WHAT WORKS WELL

1. **Large numbers/stats render MUCH better** than body text
   - 88%, 1000, 300M, 4.4T are mostly accurate
   - Numbered badges (01, 02, 03) are clear when correct
   
2. **Overall structure** is usually recognizable
   - Titles are readable
   - Layout shapes are identifiable
   - Icons are present

3. **Visual hierarchy** with size/color often works

**Strategic Implication**: Emphasize large numbers/badges, minimize descriptive text

---

## 📊 PRIORITY RECOMMENDATIONS

### Immediate (Week 1-2):
1. **Test alternative models** for text accuracy (FLUX-pro, FLUX-dev, SD 3.5)
2. **Add validation layer**:
   - Sequence validation (01→02→03...)
   - Completeness check (all requested elements present?)
   - Data logic validation (funnels decrease, dates valid)
3. **Add user warnings** about text accuracy limitations in UI
4. **Implement "Tweak" suggestions** for common text corrections

### Short-term (1 month):
1. **Text overlay feature** - Generate image, add text separately with reliable rendering
2. **Prompt optimization** based on test learnings:
   - Emphasize large numbers (they work!)
   - Minimize descriptive text (it fails)
   - Avoid complex shapes (use rectangles + visual cues)
3. **Style presets** for each infographic type with validated templates
4. **Post-processing correction** layer for common text errors

### Long-term (3+ months):
1. **Fine-tuned models** for specific content types (infographics, logos)
2. **Template-based generation** with guaranteed structure
3. **AI prompt enhancement** system that optimizes based on content type
4. **Hybrid approach**: Model generates layout/design, reliable system adds text

---

## 🎯 CONTENT-TYPE SPECIFIC NOTES

### Process Infographics
- ❌ Sequential numbering fails
- ❌ Missing final steps common
- ❌ Arrow flow logic broken
- ✅ Overall structure recognizable

### Timelines
- ❌ Dates/years corrupted (especially 4-digit years)
- ❌ Vertical connector lines inconsistent
- ✅ Timeline structure clear

### Comparison/VS Layouts
- ❌ Horizontal alignment fails
- ❌ Numbering sequence errors
- ✅ Two-column structure recognizable

### Statistics/Data
- ✅ **BEST RESULTS** - Large numbers work well!
- ❌ Grid layouts uneven
- ❌ Supporting text still garbled
- **Recommendation**: Focus on number-heavy designs

### Hierarchies/Pyramids
- ❌ Shape morphing fails (rectangles instead of trapezoids)
- ❌ Color gradients inconsistent
- ✅ Numbered badges perfect
- **Recommendation**: Use rectangles + visual cues instead of actual pyramid shapes

### Funnels
- ❌ **WORST RESULTS** - Data logic completely broken
- ❌ Metrics increase mid-funnel (impossible)
- ❌ Numbering sequence worst (01, 02, 08, 04...)
- ❌ Shape narrowing inconsistent
- **Recommendation**: Needs heavy validation or template-based approach

---

## 🔧 TECHNICAL IMPLEMENTATION NOTES

### Backend API Changes Needed:

1. **Validation Endpoint** - Add pre/post-generation validation:
```javascript
// Pseudo-code
validateInfographic(content, type) {
  if (type === 'funnel') {
    // Check metrics decrease
    validateDecreasingSequence(metrics);
  }
  if (hasNumberedSteps) {
    // Check sequence 01→02→03...
    validateSequence(numbers);
  }
  if (hasDateYear) {
    // Check year range 1900-2026
    validateYearRange(years);
  }
  return { valid, errors };
}
```

2. **Prompt Enhancement Service** - Optimize prompts by content type:
```javascript
enhancePrompt(userPrompt, contentType, styleType) {
  let enhanced = userPrompt;
  
  if (contentType === 'infographic' && styleType === 'stats') {
    // Emphasize large numbers, minimize text
    enhanced += "\nUse very large bold numbers. Keep descriptions to 3-5 words maximum.";
  }
  
  if (styleType === 'process') {
    enhanced += "\nNumber each step sequentially: 01, 02, 03, 04, 05, 06 with no gaps.";
  }
  
  return enhanced;
}
```

3. **Model Selection Logic** - Choose best model per content type:
```javascript
selectModel(contentType, styleType) {
  if (styleType === 'stats' || styleType === 'timeline') {
    return 'flux-pro'; // Better with numbers
  }
  return 'default-model';
}
```

4. **Frontend Warning Display**:
```javascript
// Show warning for infographics
if (contentType === 'infographic') {
  showWarning("Text accuracy may vary. Large numbers render best. Review and use 'Tweak' to correct any errors.");
}
```

