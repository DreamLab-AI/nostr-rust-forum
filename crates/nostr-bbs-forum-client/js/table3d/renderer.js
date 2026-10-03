// renderer.js — WebGPURenderer, on WebGPU or its WebGL 2 backend.
//
// The Rust side picks the backend from the app's render tier and passes
// `webgpu` or `webgl`; `webgl` sets `forceWebGL`. Even asked for WebGPU,
// three falls back to WebGL 2 by itself when the adapter request fails, so the
// backend reported in the `ready` event is read from the renderer after
// `init()`, never assumed.

import * as THREE from './three.js';

/**
 * Create and initialise the renderer on `canvas`. Rejects when neither
 * backend can start; the caller then keeps the DOM table.
 */
export async function createRenderer(canvas, { backend = 'webgpu', antialias = true, tier = 'high' } = {}) {
  const renderer = new THREE.WebGPURenderer({
    canvas,
    antialias,
    alpha: false,
    forceWebGL: backend === 'webgl',
    powerPreference: 'high-performance',
  });
  await renderer.init();
  const used = renderer.backend && renderer.backend.isWebGPUBackend ? 'webgpu' : 'webgl';
  // Neutral keeps the felt's hue where the operator set it; ACES would push
  // a green baize towards teal.
  renderer.toneMapping = THREE.NeutralToneMapping;
  renderer.toneMappingExposure = 1.0;
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.shadowMap.enabled = tier === 'high';
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  return { renderer, backend: used };
}

/** A cap on anisotropic filtering: plenty for felt seen at a low angle. */
export function anisotropy(renderer) {
  try {
    return Math.min(8, renderer.getMaxAnisotropy() || 1);
  } catch (_e) {
    return 1;
  }
}
