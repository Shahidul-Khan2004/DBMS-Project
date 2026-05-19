"use client";

import { useReducedMotion } from "framer-motion";

/** Matches register wizard step transition timing. */
export const AUTH_STEP_TRANSITION = { duration: 0.2 } as const;

export const authStepEnter = { opacity: 0, y: 10 } as const;
export const authStepAnimate = { opacity: 1, y: 0 } as const;
export const authStepExit = { opacity: 0, y: -6 } as const;

const authStepVisible = { opacity: 1, y: 0 } as const;
const authStepTransitionInstant = { duration: 0 } as const;

export function useAuthStepMotion() {
  const reduced = useReducedMotion();

  if (reduced) {
    return {
      initial: authStepVisible,
      animate: authStepVisible,
      exit: authStepVisible,
      transition: authStepTransitionInstant,
    };
  }

  return {
    initial: authStepEnter,
    animate: authStepAnimate,
    exit: authStepExit,
    transition: AUTH_STEP_TRANSITION,
  };
}
