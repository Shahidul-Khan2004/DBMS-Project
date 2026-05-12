import React from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";

interface LoginCardProps {
  children: React.ReactNode;
}

export const LoginCard: React.FC<LoginCardProps> = ({ children }) => {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200 px-4 sm:px-6 lg:px-8">
      <div className="w-full max-w-xl">
        <Card className="shadow-md">
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 w-fit bg-[#002D62] px-6 py-3 text-2xl font-bold tracking-[-1px] text-white">
              NIERS
            </div>
            <h1 className="text-2xl font-bold text-[#002D62]">
              Sign in to NIERS
            </h1>
            <p className="mt-2 text-gray-600">
              Access your emergency response workspace.
            </p>
          </CardHeader>
          <CardContent>{children}</CardContent>
        </Card>

        <div className="mt-8 text-center text-xs text-gray-500">
          <p>Official NIERS access portal | 2026</p>
        </div>
      </div>
    </div>
  );
};
