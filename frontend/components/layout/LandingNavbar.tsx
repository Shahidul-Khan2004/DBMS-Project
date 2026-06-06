"use client";

import { motion } from "framer-motion";
import { Menu, X } from "lucide-react";
import Link from "next/link";
import { NiersNavbar } from "@/components/layout/NiersNavbar";

const SECTION_IDS = ["why-choose", "how-it-works", "national-disaster"] as const;
export type LandingSectionId = (typeof SECTION_IDS)[number];
type SectionId = LandingSectionId;

function isSectionId(id: string): id is SectionId {
  return (SECTION_IDS as readonly string[]).includes(id);
}

interface LandingNavbarProps {
  isMobileMenuOpen: boolean;
  setIsMobileMenuOpen: (open: boolean | ((prev: boolean) => boolean)) => void;
  selectedSection: SectionId | null;
  setSelectedSection: (id: SectionId | null) => void;
  lang: "en" | "bn";
  setLang: (lang: "en" | "bn") => void;
}

export function LandingNavbar({
  isMobileMenuOpen,
  setIsMobileMenuOpen,
  selectedSection,
  setSelectedSection,
  lang,
  setLang,
}: LandingNavbarProps) {
  const scrollToSection = (id: string) => {
    setIsMobileMenuOpen(false);
    if (isSectionId(id)) {
      setSelectedSection(id);
    }
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
  };

  const desktopSectionNavClass = (id: SectionId) =>
    [
      "cursor-pointer rounded-lg px-3 py-2 transition-colors landing-text-nav",
      selectedSection === id
        ? "text-[#002D62] font-medium hover:text-[#002D62]"
        : "text-gray-700 font-medium hover:text-[#006747]",
    ].join(" ");

  const mobileSectionNavClass = (id: SectionId) =>
    [
      "cursor-pointer rounded-lg px-3 py-2 transition-colors landing-text-nav font-medium",
      selectedSection === id
        ? "text-[#002D62] hover:text-[#002D62]"
        : "text-gray-700 hover:text-[#006747]",
    ].join(" ");

  const langToggleClass = (code: "en" | "bn") =>
    [
      "cursor-pointer rounded-full font-medium transition-colors landing-text-body px-[var(--landing-lang-px)] py-[var(--landing-lang-py)]",
      lang === code
        ? "bg-[#002D62] text-white"
        : "text-gray-700 hover:bg-gray-200",
    ].join(" ");

  return (
    <NiersNavbar
      contained
      centerContent={
        <div className="hidden min-w-0 items-center gap-[var(--nav-gap)] lg:flex">
          <button
            type="button"
            onClick={() => scrollToSection("why-choose")}
            className={desktopSectionNavClass("why-choose")}
          >
            About NIERS
          </button>
          <button
            type="button"
            onClick={() => scrollToSection("national-disaster")}
            className={desktopSectionNavClass("national-disaster")}
          >
            National Disasters
          </button>
          <button
            type="button"
            onClick={() => scrollToSection("how-it-works")}
            className={desktopSectionNavClass("how-it-works")}
          >
            How It Works
          </button>
        </div>
      }
      trailingContent={
        <>
          <div className="hidden items-center gap-[var(--nav-gap)] lg:flex">
            <Link
              href="/auth/login"
              className="landing-text-body cursor-pointer rounded-2xl border-2 border-primary-600 px-[var(--landing-btn-px)] py-[var(--landing-btn-py)] font-semibold text-primary-600 transition-colors hover:border-primary-700 hover:bg-gray-50 hover:text-primary-700"
            >
              Login
            </Link>
            <Link
              href="/auth/register"
              className="landing-text-body cursor-pointer rounded-2xl bg-[#002D62] px-[var(--landing-btn-px)] py-[var(--landing-btn-py)] font-semibold text-white transition-colors hover:bg-[#001F4A]"
            >
              Register
            </Link>
          </div>

          <button
            type="button"
            id="mobile-menu-button"
            aria-expanded={isMobileMenuOpen}
            aria-controls="mobile-nav-panel"
            onClick={() => setIsMobileMenuOpen((o) => !o)}
            className="cursor-pointer rounded-lg p-2.5 text-gray-700 transition-colors hover:bg-gray-100 lg:hidden"
          >
            <span className="sr-only">
              {isMobileMenuOpen ? "Close menu" : "Open menu"}
            </span>
            {isMobileMenuOpen ? (
              <X className="h-6 w-6" aria-hidden />
            ) : (
              <Menu className="h-6 w-6" aria-hidden />
            )}
          </button>
        </>
      }
      bottomPanel={
        isMobileMenuOpen ? (
          <motion.div
            id="mobile-nav-panel"
            role="region"
            aria-labelledby="mobile-menu-button"
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.18 }}
            className="border-t border-gray-200 bg-zinc-200 lg:hidden"
          >
            <div className="landing-container">
              <div className="space-y-1 py-5">
                <div className="mb-2 border-b border-gray-100 pb-4">
                  <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">
                    Language
                  </p>
                  <div
                    className="flex w-fit rounded-full bg-gray-100 p-1.5"
                    role="group"
                    aria-label="Language"
                  >
                    <button
                      type="button"
                      className={langToggleClass("en")}
                      aria-pressed={lang === "en"}
                      onClick={() => setLang("en")}
                    >
                      EN
                    </button>
                    <button
                      type="button"
                      className={langToggleClass("bn")}
                      aria-pressed={lang === "bn"}
                      onClick={() => setLang("bn")}
                    >
                      বাংলা
                    </button>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => scrollToSection("why-choose")}
                  className={`${mobileSectionNavClass("why-choose")} block w-full py-3 text-left`}
                >
                  About NIERS
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection("national-disaster")}
                  className={`${mobileSectionNavClass("national-disaster")} block w-full py-3 text-left`}
                >
                  National Disasters
                </button>
                <button
                  type="button"
                  onClick={() => scrollToSection("how-it-works")}
                  className={`${mobileSectionNavClass("how-it-works")} block w-full py-3 text-left`}
                >
                  How It Works
                </button>

                <div className="mt-2 flex flex-col gap-3 border-t border-gray-200 pt-4">
                  <Link
                    href="/auth/login"
                    onClick={() => setIsMobileMenuOpen(false)}
                    className="w-full cursor-pointer rounded-2xl border-2 border-primary-600 py-3.5 text-center text-base font-semibold text-primary-600 transition-colors hover:border-primary-700 hover:bg-gray-50 hover:text-primary-700"
                  >
                    Login
                  </Link>
                  <Link
                    href="/auth/register"
                    onClick={() => setIsMobileMenuOpen(false)}
                    className="w-full cursor-pointer rounded-2xl bg-[#002D62] py-3.5 text-center text-base font-semibold text-white transition-colors hover:bg-[#001F4A]"
                  >
                    Register
                  </Link>
                </div>
              </div>
            </div>
          </motion.div>
        ) : null
      }
    />
  );
}
