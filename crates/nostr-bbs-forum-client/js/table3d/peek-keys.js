// peek-keys.js — keyboard access to card inspection.
//
// The canvas is one element and hidden from assistive technology, so the
// page renders one real <button data-t3d-peek="hole|board|villain"> per
// inspectable group beside it (src/components/table3d.rs). This module owns
// their behaviour: it shows only the groups the table has face up, lays each
// button over its group's cards on screen (so its focus ring frames them,
// following the cards as they lift), and turns keys into inspections: Tab
// moves between groups in document order, Enter or Space toggles, Escape
// drops, and moving focus away drops too. Keys it handles stop here, so the
// table page's own shortcuts (Enter deals the next hand) never see them. The
// buttons take no pointer events: the mouse hovers, the finger taps the scene.
//
// No three and no document: it works on whatever elements `root` holds, so
// node tests drive it with stand-ins.

export class PeekKeys {
  /**
   * @param {{querySelectorAll(sel: string): Iterable<any>} | null} root
   * @param {{onToggle(group: string): void, onDrop(group: string): boolean}} handlers
   */
  constructor(root, { onToggle, onDrop }) {
    this.buttons = root ? [...root.querySelectorAll('[data-t3d-peek]')] : [];
    this.bound = [];
    this.last = new Map();
    for (const el of this.buttons) {
      const group = el.getAttribute('data-t3d-peek');
      const keydown = (e) => {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
          // handled here, so the button's own click activation never doubles
          // it, and the page's own Enter (deal the next hand) never sees it
          e.preventDefault();
          e.stopPropagation();
          onToggle(group);
        } else if (e.key === 'Escape') {
          if (onDrop(group)) {
            e.preventDefault();
            e.stopPropagation();
          }
        }
      };
      const blur = () => onDrop(group);
      el.addEventListener('keydown', keydown);
      el.addEventListener('blur', blur);
      this.bound.push([el, keydown, blur]);
    }
  }

  /**
   * Show the buttons for `available` groups (a Set), mark the `active` one
   * pressed, and lay each over its on-screen `rects.get(group)` ({x, y, w,
   * h} in CSS pixels of the stage).
   */
  sync(available, active, rects) {
    for (const el of this.buttons) {
      const group = el.getAttribute('data-t3d-peek');
      const on = available.has(group);
      const r = rects && rects.get(group);
      const pressed = on && active === group ? 'true' : 'false';
      const box = r ? `${r.x.toFixed(1)},${r.y.toFixed(1)},${r.w.toFixed(1)},${r.h.toFixed(1)}` : '';
      const key = `${on}|${pressed}|${box}`;
      if (this.last.get(el) === key) continue;
      this.last.set(el, key);
      el.hidden = !on;
      el.setAttribute('aria-pressed', pressed);
      if (r) {
        el.style.transform = `translate(${r.x.toFixed(1)}px, ${r.y.toFixed(1)}px)`;
        el.style.width = `${r.w.toFixed(1)}px`;
        el.style.height = `${r.h.toFixed(1)}px`;
      }
    }
  }

  /** Unbind every listener and hide the buttons. */
  dispose() {
    for (const [el, keydown, blur] of this.bound) {
      el.removeEventListener('keydown', keydown);
      el.removeEventListener('blur', blur);
      el.hidden = true;
      el.setAttribute('aria-pressed', 'false');
    }
    this.bound = [];
    this.buttons = [];
    this.last.clear();
  }
}
