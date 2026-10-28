'use client';

import { useEffect, useState } from 'react';
import { riskScoreColor, riskScoreBgColor } from '@/lib/utils';

interface RiskGaugeProps {
  score: number;
  size?: number;
  label?: string;
}

export default function RiskGauge({ score, size = 120, label = 'Risk Score' }: RiskGaugeProps) {
  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    let startTime: number | null = null;
    const duration = 1000;
    let animationFrame: number;

    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progressRatio = Math.min((timestamp - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progressRatio, 3);
      setDisplayScore(Math.round(eased * score));

      if (progressRatio < 1) {
        animationFrame = requestAnimationFrame(animate);
      }
    };

    animationFrame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrame);
  }, [score]);

  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (displayScore / 100) * circumference;
  const color = riskScoreBgColor(score);

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} className="-rotate-90">
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#292929"
          strokeWidth={6}
          fill="none"
        />
        {/* Progress arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={6}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          style={{ transition: 'stroke-dashoffset 0.1s ease-out' }}
        />
        {/* Score text (needs to un-rotate) */}
        <text
          x={size / 2}
          y={size / 2}
          textAnchor="middle"
          dominantBaseline="central"
          className={`text-2xl font-bold ${riskScoreColor(score)} fill-current`}
          transform={`rotate(90, ${size / 2}, ${size / 2})`}
        >
          {displayScore}
        </text>
      </svg>
      <span className="text-xs text-tn-muted">{label}</span>
    </div>
  );
}

