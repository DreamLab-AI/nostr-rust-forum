// three.js — the one place the table names its three.js build.
//
// The vendored files live at <public-url>/vendor/three-0.186.1/ (copied by
// Trunk from assets/vendor/, see VENDORED.md) and this module at
// <public-url>/table3d/, so a relative import reaches them from any route and
// under any --public-url. Every other table3d module imports three from here,
// so a version bump is one line.
//
// `three` is the WebGPU build: it carries the whole core, WebGPURenderer with
// its WebGL 2 backend, the node materials and TSL.

export * from '../vendor/three-0.186.1/three.webgpu.min.js';
export { RoomEnvironment } from '../vendor/three-0.186.1/RoomEnvironment.min.js';
