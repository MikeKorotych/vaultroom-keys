"use client";

import { useEffect, useRef } from "react";

const FRAME_INTERVAL = 1000 / 30;

export function DotPlasmaBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const context = canvas.getContext("2d", { alpha: true });
    if (!context) return;

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0;
    let lastFrame = 0;
    let width = 0;
    let height = 0;

    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    };

    const draw = (timestamp: number) => {
      if (timestamp - lastFrame < FRAME_INTERVAL && !reducedMotion.matches) {
        frame = window.requestAnimationFrame(draw);
        return;
      }
      lastFrame = timestamp;
      context.clearRect(0, 0, width, height);

      const time = reducedMotion.matches ? 0 : timestamp * 0.00032;
      const horizon = height * 0.27;
      const rows = Math.max(30, Math.min(44, Math.round(height / 18)));
      const columns = Math.max(48, Math.min(82, Math.round(width / 19)));
      const centerX = width * 0.55;

      context.fillStyle = "#f5f5f2";
      for (let row = 0; row < rows; row += 1) {
        const depth = row / Math.max(1, rows - 1);
        const projectedDepth = Math.pow(depth, 1.72);
        const baseY = horizon + projectedDepth * (height - horizon + 72);
        const spread = width * (0.13 + depth * 0.72);

        for (let column = 0; column < columns; column += 1) {
          const across = column / Math.max(1, columns - 1) * 2 - 1;
          const x = centerX + across * spread;
          const wave =
            Math.sin(across * 7.2 + time * 1.4 + depth * 2.4) * 0.58 +
            Math.cos(depth * 10.5 - time * 1.8 + across * 2.8) * 0.42;
          const y = baseY + wave * (5 + depth * 38);
          const horizontalFade = Math.max(0, 1 - Math.pow(Math.abs((x - width / 2) / (width * 0.62)), 2.4));
          const verticalFade = Math.sin(Math.min(1, depth) * Math.PI * 0.92);
          const alpha = Math.max(0, horizontalFade * verticalFade * (0.08 + depth * 0.42));
          if (alpha < 0.018 || y < horizon - 8 || y > height + 4) continue;

          const dot = 0.55 + projectedDepth * 1.2;
          context.globalAlpha = alpha;
          context.fillRect(x - dot / 2, y - dot / 2, dot, dot);
        }
      }
      context.globalAlpha = 1;

      if (!reducedMotion.matches && document.visibilityState === "visible") {
        frame = window.requestAnimationFrame(draw);
      }
    };

    const restart = () => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(draw);
    };

    resize();
    restart();
    window.addEventListener("resize", resize, { passive: true });
    window.addEventListener("resize", restart, { passive: true });
    document.addEventListener("visibilitychange", restart);
    reducedMotion.addEventListener("change", restart);

    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      window.removeEventListener("resize", restart);
      document.removeEventListener("visibilitychange", restart);
      reducedMotion.removeEventListener("change", restart);
    };
  }, []);

  return <canvas ref={canvasRef} className="dotPlasma" aria-hidden="true" />;
}
