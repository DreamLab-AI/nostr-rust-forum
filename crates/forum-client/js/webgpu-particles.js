// WebGPU particle system with golden-ratio spiral, mouse interaction, and bloom glow.
// ADR-020: GPU-accelerated hero background for Nostr BBS forum.

const PARTICLE_WGSL = `
struct Particle {
  pos: vec2f,
  vel: vec2f,
  life: f32,
  size: f32,
};

struct Uniforms {
  time: f32,
  delta: f32,
  width: f32,
  height: f32,
  mouse_x: f32,
  mouse_y: f32,
};

@group(0) @binding(0) var<storage, read_write> particles: array<Particle>;
@group(0) @binding(1) var<uniform> uniforms: Uniforms;

@compute @workgroup_size(64)
fn update(@builtin(global_invocation_id) id: vec3u) {
  let i = id.x;
  if (i >= arrayLength(&particles)) { return; }

  var p = particles[i];

  // Golden ratio spiral target positions
  let golden_angle = 2.39996323;
  let fi = f32(i);
  let total = f32(arrayLength(&particles));
  let base_angle = fi * golden_angle + uniforms.time * 0.08;
  let radius = sqrt(fi / total) * min(uniforms.width, uniforms.height) * 0.38;

  let cx = uniforms.width * 0.5;
  let cy = uniforms.height * 0.5;

  // Layered sinusoidal drift (two octaves, phi-scaled)
  let phi = 1.618033988;
  let drift_x = sin(uniforms.time * 0.25 + fi * 0.1) * 12.0
              + cos(uniforms.time * 0.13 + fi * phi * 0.1) * 6.0;
  let drift_y = cos(uniforms.time * 0.21 + fi * 0.13) * 12.0
              + sin(uniforms.time * 0.17 + fi * 0.06) * 6.0;

  let target = vec2f(
    cx + cos(base_angle) * radius + drift_x,
    cy + sin(base_angle) * radius + drift_y,
  );

  // Mouse repulsion — particles flee the cursor
  let mouse = vec2f(uniforms.mouse_x, uniforms.mouse_y);
  let to_mouse = p.pos - mouse;
  let mouse_dist = length(to_mouse);
  let repulsion = select(
    vec2f(0.0),
    normalize(to_mouse) * 180.0 / max(mouse_dist, 1.0),
    mouse_dist < 140.0 && mouse_dist > 0.1
  );

  // Spring toward target + repulsion
  let spring = (target - p.pos) * 0.025;
  p.vel += spring + repulsion * uniforms.delta;
  p.vel *= 0.94; // damping
  p.pos += p.vel * uniforms.delta;

  // Breathing glow — unique phase per particle
  p.life = 0.45 + 0.55 * sin(uniforms.time * 1.8 + fi * 0.17);

  // Size pulse
  p.size = 1.5 + p.life * 2.5;

  particles[i] = p;
}

struct VertexOutput {
  @builtin(position) pos: vec4f,
  @location(0) alpha: f32,
  @location(1) uv: vec2f,
  @location(2) accent: f32,
};

@vertex
fn vs_main(
  @builtin(vertex_index) vi: u32,
  @builtin(instance_index) ii: u32,
) -> VertexOutput {
  let p = particles[ii];

  // Instanced quad corners (triangle-strip order)
  let corners = array(vec2f(-1.0, -1.0), vec2f(1.0, -1.0), vec2f(-1.0, 1.0), vec2f(1.0, 1.0));
  let uv = corners[vi] * 0.5 + 0.5;

  let screen_pos = vec2f(
    (p.pos.x + corners[vi].x * p.size) / uniforms.width * 2.0 - 1.0,
    1.0 - (p.pos.y + corners[vi].y * p.size) / uniforms.height * 2.0,
  );

  // ~14% of particles get ice-blue accent
  let is_accent = select(0.0, 1.0, (ii % 7u) == 3u);

  var out: VertexOutput;
  out.pos = vec4f(screen_pos, 0.0, 1.0);
  out.alpha = p.life;
  out.uv = uv;
  out.accent = is_accent;
  return out;
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4f {
  let dist = length(in.uv - vec2f(0.5));

  // Soft circular falloff with bloom halo
  let core = smoothstep(0.5, 0.15, dist);
  let halo = smoothstep(0.5, 0.0, dist) * 0.35;
  let glow = core + halo;

  // Amber: rgb(251, 191, 36) => (0.984, 0.749, 0.141)
  // Ice-blue: rgb(147, 197, 253) => (0.576, 0.773, 0.992)
  let amber = vec3f(0.984, 0.749, 0.141);
  let ice_blue = vec3f(0.576, 0.773, 0.992);
  let base_color = mix(amber, ice_blue, in.accent);

  // Brighten core, warm the edges
  let color = mix(base_color, vec3f(1.0, 0.92, 0.7), core * 0.3);

  return vec4f(color * glow, glow * in.alpha * 0.75);
}
`;

// --- Connection lines fragment shader ---
const CONN_WGSL = `
struct Uniforms {
  time: f32,
  delta: f32,
  width: f32,
  height: f32,
  mouse_x: f32,
  mouse_y: f32,
};

struct ConnVertex {
  @builtin(position) pos: vec4f,
  @location(0) alpha: f32,
};

@group(0) @binding(1) var<uniform> uniforms: Uniforms;

@vertex
fn conn_vs(@location(0) position: vec2f, @location(1) alpha: f32) -> ConnVertex {
  var out: ConnVertex;
  out.pos = vec4f(
    position.x / uniforms.width * 2.0 - 1.0,
    1.0 - position.y / uniforms.height * 2.0,
    0.0, 1.0
  );
  out.alpha = alpha;
  return out;
}

@fragment
fn conn_fs(in: ConnVertex) -> @location(0) vec4f {
  // Amber connection lines with subtle warmth
  return vec4f(0.984, 0.749, 0.141, in.alpha * 0.12);
}
`;

/**
 * Initialize the WebGPU particle system on the given canvas.
 * @param {HTMLCanvasElement} canvas
 * @param {number} particleCount
 * @returns {Promise<{destroy: Function}|null>}
 */
export async function initWebGPUParticles(canvas, particleCount = 120) {
  const adapter = await navigator.gpu?.requestAdapter();
  if (!adapter) return null;

  const device = await adapter.requestDevice();
  const ctx = canvas.getContext('webgpu');
  if (!ctx) return null;

  const format = navigator.gpu.getPreferredCanvasFormat();
  ctx.configure({ device, format, alphaMode: 'premultiplied' });

  // -- Particle buffer --
  const PARTICLE_STRIDE = 6 * 4; // pos(2) + vel(2) + life(1) + size(1) = 6 floats
  const particleBuffer = device.createBuffer({
    size: particleCount * PARTICLE_STRIDE,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.VERTEX,
  });

  // Initialize particles on golden-ratio spiral
  const initData = new Float32Array(particleCount * 6);
  const goldenAngle = 2.39996323;
  const maxR = Math.min(canvas.width, canvas.height) * 0.38;
  for (let i = 0; i < particleCount; i++) {
    const angle = i * goldenAngle;
    const r = Math.sqrt(i / particleCount) * maxR;
    const off = i * 6;
    initData[off + 0] = canvas.width / 2 + Math.cos(angle) * r;
    initData[off + 1] = canvas.height / 2 + Math.sin(angle) * r;
    initData[off + 2] = 0; // vx
    initData[off + 3] = 0; // vy
    initData[off + 4] = Math.random(); // life
    initData[off + 5] = 1.5 + Math.random() * 2.5; // size
  }
  device.queue.writeBuffer(particleBuffer, 0, initData);

  // -- Uniform buffer --
  const uniformBuffer = device.createBuffer({
    size: 6 * 4, // time, delta, width, height, mouse_x, mouse_y
    usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
  });

  // -- Shader modules --
  const particleShader = device.createShaderModule({ code: PARTICLE_WGSL });
  // Connections use a separate simple shader (CPU-built vertex buffer)
  // Skipped for now to keep GPU pipeline clean — connections drawn via readback-free approach

  // -- Bind group layout --
  const bindGroupLayout = device.createBindGroupLayout({
    entries: [
      {
        binding: 0,
        visibility: GPUShaderStage.COMPUTE | GPUShaderStage.VERTEX,
        buffer: { type: 'storage' },
      },
      {
        binding: 1,
        visibility: GPUShaderStage.COMPUTE | GPUShaderStage.VERTEX | GPUShaderStage.FRAGMENT,
        buffer: { type: 'uniform' },
      },
    ],
  });

  const pipelineLayout = device.createPipelineLayout({
    bindGroupLayouts: [bindGroupLayout],
  });

  const bindGroup = device.createBindGroup({
    layout: bindGroupLayout,
    entries: [
      { binding: 0, resource: { buffer: particleBuffer } },
      { binding: 1, resource: { buffer: uniformBuffer } },
    ],
  });

  // -- Compute pipeline --
  const computePipeline = device.createComputePipeline({
    layout: pipelineLayout,
    compute: { module: particleShader, entryPoint: 'update' },
  });

  // -- Render pipeline (instanced quads with additive blend) --
  const renderPipeline = device.createRenderPipeline({
    layout: pipelineLayout,
    vertex: {
      module: particleShader,
      entryPoint: 'vs_main',
    },
    fragment: {
      module: particleShader,
      entryPoint: 'fs_main',
      targets: [{
        format,
        blend: {
          color: { srcFactor: 'src-alpha', dstFactor: 'one', operation: 'add' },
          alpha: { srcFactor: 'one', dstFactor: 'one', operation: 'add' },
        },
      }],
    },
    primitive: { topology: 'triangle-strip' },
  });

  // -- State --
  let running = true;
  let lastTime = performance.now();
  let mouseX = canvas.width / 2;
  let mouseY = canvas.height / 2;
  let resizeObserver = null;

  // Mouse tracking
  const onMouseMove = (e) => {
    const rect = canvas.getBoundingClientRect();
    mouseX = (e.clientX - rect.left) * (canvas.width / rect.width);
    mouseY = (e.clientY - rect.top) * (canvas.height / rect.height);
  };
  canvas.addEventListener('mousemove', onMouseMove);

  // Touch tracking
  const onTouchMove = (e) => {
    if (e.touches.length > 0) {
      const rect = canvas.getBoundingClientRect();
      mouseX = (e.touches[0].clientX - rect.left) * (canvas.width / rect.width);
      mouseY = (e.touches[0].clientY - rect.top) * (canvas.height / rect.height);
    }
  };
  canvas.addEventListener('touchmove', onTouchMove, { passive: true });

  // Resize handling
  const handleResize = () => {
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    ctx.configure({ device, format, alphaMode: 'premultiplied' });
  };

  if (typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(canvas);
  }

  // -- Animation loop --
  function frame(now) {
    if (!running) return;

    const dt = Math.min((now - lastTime) / 1000, 0.05);
    lastTime = now;

    // Update uniforms
    const uniforms = new Float32Array([
      now / 1000, dt, canvas.width, canvas.height, mouseX, mouseY,
    ]);
    device.queue.writeBuffer(uniformBuffer, 0, uniforms);

    const encoder = device.createCommandEncoder();

    // Compute pass: update particle positions
    const computePass = encoder.beginComputePass();
    computePass.setPipeline(computePipeline);
    computePass.setBindGroup(0, bindGroup);
    computePass.dispatchWorkgroups(Math.ceil(particleCount / 64));
    computePass.end();

    // Render pass: draw particles as instanced glow quads
    let textureView;
    try {
      textureView = ctx.getCurrentTexture().createView();
    } catch (_) {
      // Context lost or canvas resized — skip frame
      requestAnimationFrame(frame);
      return;
    }

    const renderPass = encoder.beginRenderPass({
      colorAttachments: [{
        view: textureView,
        clearValue: { r: 0.067, g: 0.094, b: 0.153, a: 1.0 }, // #111827
        loadOp: 'clear',
        storeOp: 'store',
      }],
    });
    renderPass.setPipeline(renderPipeline);
    renderPass.setBindGroup(0, bindGroup);
    renderPass.draw(4, particleCount); // 4 vertices per quad, instanced
    renderPass.end();

    device.queue.submit([encoder.finish()]);
    requestAnimationFrame(frame);
  }

  requestAnimationFrame(frame);

  // -- Return handle --
  return {
    destroy() {
      running = false;
      canvas.removeEventListener('mousemove', onMouseMove);
      canvas.removeEventListener('touchmove', onTouchMove);
      if (resizeObserver) {
        resizeObserver.disconnect();
      }
      // Allow GC — don't destroy device, other contexts may use it
    },
  };
}

/**
 * Destroy a previously-initialized particle system.
 * @param {{destroy: Function}|null} handle
 */
export function destroyWebGPUParticles(handle) {
  if (handle?.destroy) handle.destroy();
}
