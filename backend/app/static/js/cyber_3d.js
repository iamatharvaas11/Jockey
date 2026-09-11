/**
 * JOCKY 3D Holographic Cyber-Security Visualizer (Three.js)
 * Generates interactive 3D cybersecurity network spheres, floating particles, and interactive nodes.
 */

window.Cyber3D = {
  // Mini HUD Holographic Network Sphere (used in Navbar / Dashboard)
  initNetworkGlobe(canvasId, containerId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !window.THREE) return null;

    const container = document.getElementById(containerId) || canvas.parentElement;
    const width = container.clientWidth || 140;
    const height = container.clientHeight || 140;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 2.4;

    const renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Outer wireframe icosahedron
    const sphereGeo = new THREE.IcosahedronGeometry(0.88, 2);
    const sphereMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      wireframe: true,
      transparent: true,
      opacity: 0.35
    });
    const globe = new THREE.Mesh(sphereGeo, sphereMat);
    scene.add(globe);

    // Inner core glowing sphere
    const coreGeo = new THREE.IcosahedronGeometry(0.48, 1);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x00ff9d,
      wireframe: true,
      transparent: true,
      opacity: 0.65
    });
    const core = new THREE.Mesh(coreGeo, coreMat);
    scene.add(core);

    // Glowing network node points on surface
    const pointsGeo = new THREE.BufferGeometry();
    const pos = sphereGeo.attributes.position.array;
    pointsGeo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    const pointsMat = new THREE.PointsMaterial({
      color: 0x00ff9d,
      size: 0.05,
      transparent: true,
      opacity: 0.9
    });
    const nodePoints = new THREE.Points(pointsGeo, pointsMat);
    scene.add(nodePoints);

    // Orbital radar ring
    const ringGeo = new THREE.RingGeometry(1.05, 1.08, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.4
    });
    const ring = new THREE.Mesh(ringGeo, ringMat);
    ring.rotation.x = Math.PI / 3;
    scene.add(ring);

    // Mouse parallax tracking
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;

    window.addEventListener('mousemove', (e) => {
      const rect = canvas.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      mouseX = (e.clientX - cx) * 0.0015;
      mouseY = (e.clientY - cy) * 0.0015;
    });

    let animId;
    function animate() {
      animId = requestAnimationFrame(animate);

      // Smooth rotation
      globe.rotation.y += 0.005;
      globe.rotation.x += 0.002;
      core.rotation.y -= 0.008;
      core.rotation.z += 0.004;
      ring.rotation.z += 0.01;

      // Mouse parallax easing
      targetX += (mouseX - targetX) * 0.05;
      targetY += (mouseY - targetY) * 0.05;
      scene.rotation.y = targetX;
      scene.rotation.x = targetY;

      renderer.render(scene, camera);
    }
    animate();

    // Resize handler
    const onResize = () => {
      if (!container) return;
      const w = container.clientWidth || width;
      const h = container.clientHeight || height;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', onResize);

    return { scene, renderer, destroy: () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', onResize);
    }};
  },

  // Full-Screen Cyber Security Matrix (Used in Login / Register Background)
  initSecurityMatrix(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !window.THREE) return null;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 1, 1000);
    camera.position.z = 400;

    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Floating Cyber Particles Grid
    const particleCount = 450;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    const colorGreen = new THREE.Color(0x00ff9d);
    const colorCyan = new THREE.Color(0x00f0ff);
    const colorBlue = new THREE.Color(0x0284c7);

    for (let i = 0; i < particleCount * 3; i += 3) {
      positions[i] = (Math.random() - 0.5) * 800;
      positions[i + 1] = (Math.random() - 0.5) * 800;
      positions[i + 2] = (Math.random() - 0.5) * 600;

      const mixed = Math.random() > 0.6 ? colorGreen : (Math.random() > 0.3 ? colorCyan : colorBlue);
      colors[i] = mixed.r;
      colors[i + 1] = mixed.g;
      colors[i + 2] = mixed.b;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
      size: 3.5,
      vertexColors: true,
      transparent: true,
      opacity: 0.6,
      blending: THREE.AdditiveBlending
    });

    const particles = new THREE.Points(geometry, material);
    scene.add(particles);

    // Floating central rotating cyber dodecahedron
    const polyGeo = new THREE.DodecahedronGeometry(90, 1);
    const polyMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      wireframe: true,
      transparent: true,
      opacity: 0.25
    });
    const centralPoly = new THREE.Mesh(polyGeo, polyMat);
    scene.add(centralPoly);

    // Inner glowing shield core
    const innerGeo = new THREE.OctahedronGeometry(55, 0);
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0x00ff9d,
      wireframe: true,
      transparent: true,
      opacity: 0.5
    });
    const innerCore = new THREE.Mesh(innerGeo, innerMat);
    scene.add(innerCore);

    let mouseX = 0, mouseY = 0;
    window.addEventListener('mousemove', (e) => {
      mouseX = (e.clientX - window.innerWidth / 2) * 0.25;
      mouseY = (e.clientY - window.innerHeight / 2) * 0.25;
    });

    let animId;
    function animate() {
      animId = requestAnimationFrame(animate);

      centralPoly.rotation.x += 0.003;
      centralPoly.rotation.y += 0.005;
      innerCore.rotation.x -= 0.006;
      innerCore.rotation.z += 0.004;

      particles.rotation.y += 0.0008;

      camera.position.x += (mouseX - camera.position.x) * 0.03;
      camera.position.y += (-mouseY - camera.position.y) * 0.03;
      camera.lookAt(scene.position);

      renderer.render(scene, camera);
    }
    animate();

    const handleResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };
    window.addEventListener('resize', handleResize);

    return { destroy: () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
    }};
  }
};

