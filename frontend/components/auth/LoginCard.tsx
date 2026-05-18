import React from "react";
import Link from "next/link";

interface LoginCardProps {
  children: React.ReactNode;
}

export const LoginCard: React.FC<LoginCardProps> = ({ children }) => {
  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,rgba(0,103,71,0.10),transparent_30%),linear-gradient(135deg,#EEF6FB_0%,#F3FAF7_48%,#EAF3FB_100%)] lg:min-h-[100svh]">
      <nav className="fixed inset-x-0 top-0 z-50 w-full border-b border-gray-200 bg-zinc-200/95 backdrop-blur-md">
        <div className="w-full px-4 sm:px-6 md:px-5 lg:px-8 xl:px-10 2xl:px-12">
          <div className="flex min-h-24 items-center justify-between gap-3 py-4 md:min-h-28 md:gap-4 md:py-5 lg:min-h-32 lg:gap-6">
            <Link
              href="/"
              className="flex shrink-0 cursor-pointer items-center rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
            >
              <div className="bg-[#002D62] px-7 py-3 text-2xl font-bold tracking-[-1px] text-white md:px-8 md:py-3.5 md:text-3xl lg:px-9 lg:py-4 lg:text-[2.25rem]">
                NIERS
              </div>
            </Link>
            <Link
              href="/auth/register"
              className="cursor-pointer rounded-2xl border-2 border-primary-600 px-7 py-3 text-base font-semibold text-primary-600 transition-colors hover:border-primary-700 hover:bg-gray-50 hover:text-primary-700 md:px-8 md:py-3.5 lg:text-lg"
            >
              Register
            </Link>
          </div>
        </div>
      </nav>

      <main className="mx-auto flex min-h-screen max-w-[1360px] flex-col items-center px-6 pb-6 pt-[calc(96px+3rem)] lg:min-h-[100svh] lg:justify-center lg:pt-[128px]">
        <div className="mb-7 max-w-xl text-center">
          <h1 className="text-4xl font-extrabold tracking-tight text-[#002D62] lg:text-[2.65rem] lg:leading-[1.05]">
            Sign in to NIERS
          </h1>
          <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600">
            Access your National Integrated Emergency Response System workspace.
          </p>
        </div>

        <section className="w-full max-w-[640px]">
          <div className="flex min-h-[390px] items-center justify-center rounded-[2rem] border border-[#C9D6E3] bg-[#E8EDF3]/70 p-6 shadow-xl shadow-[#002D62]/10 sm:p-12 [&_label]:text-[#0F172A] [&_p]:text-[#64748B] [&_[id$='-error']]:text-[#DA291C]">
            <div className="mx-auto w-full max-w-[540px]">
              <div className="mb-6">
                <h2 className="text-xl font-bold text-[#002D62] sm:text-2xl">
                  Welcome back
                </h2>
                <p className="mt-1 text-sm text-[#64748B] sm:text-base">
                  Use your registered email and password to continue.
                </p>
              </div>
              {children}
            </div>
          </div>
          <p className="mt-4 text-center text-xs text-[#64748B]">
            Official NIERS access portal | 2026
          </p>
        </section>
      </main>
    </div>
  );
};
