"use client";

import { motion, useReducedMotion, type HTMLMotionProps } from "framer-motion";
import type { ReactNode } from "react";

type Base = {
  children: ReactNode;
  className?: string;
  /** Stagger offset in seconds (e.g. grid items). */
  delay?: number;
};

const viewport = { once: true, margin: "0px 0px -10% 0px" } as const;

function useRevealMotion(delay: number) {
  const reduce = useReducedMotion();
  if (reduce) {
    return {
      initial: { opacity: 1, y: 0 },
      whileInView: { opacity: 1, y: 0 },
      viewport,
      transition: { duration: 0 },
    };
  }
  return {
    initial: { opacity: 0, y: 24 },
    whileInView: { opacity: 1, y: 0 },
    viewport,
    transition: {
      duration: 0.55,
      ease: [0.25, 0.1, 0.25, 1] as [number, number, number, number],
      delay,
    },
  };
}

type DivProps = Base &
  Omit<
    HTMLMotionProps<"div">,
    keyof Base | "initial" | "whileInView" | "viewport" | "transition"
  >;

export function RevealOnScroll({
  children,
  className,
  delay = 0,
  ...rest
}: DivProps) {
  const m = useRevealMotion(delay);
  return (
    <motion.div className={className} {...m} {...rest}>
      {children}
    </motion.div>
  );
}

type BtnProps = Base &
  Omit<
    HTMLMotionProps<"button">,
    | keyof Base
    | "initial"
    | "whileInView"
    | "viewport"
    | "transition"
    | "type"
  >;

export function RevealOnScrollButton({
  children,
  className,
  delay = 0,
  ...rest
}: BtnProps) {
  const m = useRevealMotion(delay);
  return (
    <motion.button type="button" className={className} {...m} {...rest}>
      {children}
    </motion.button>
  );
}
