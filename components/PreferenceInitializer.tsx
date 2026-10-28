'use client';

import { useEffect } from 'react';
import { getInterfacePreferences } from '@/lib/storage';

export default function PreferenceInitializer() {
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const preferences = getInterfacePreferences();
      document.documentElement.dataset.density = preferences.compactTables ? 'compact' : 'comfortable';
      document.documentElement.dataset.reduceMotion = preferences.reduceMotion ? 'true' : 'false';
    });

    return () => window.cancelAnimationFrame(frame);
  }, []);

  return null;
}
