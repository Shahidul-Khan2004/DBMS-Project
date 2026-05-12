import React from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";

interface RegistrationCardProps {
  children: React.ReactNode;
}

export const RegistrationCard: React.FC<RegistrationCardProps> = ({
  children,
}) => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-emerald-50/40 via-[#EFF6FF] to-zinc-200 px-4 py-8 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-xl">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 w-fit bg-[#002D62] px-6 py-3 text-2xl font-bold tracking-[-1px] text-white">
            NIERS
          </div>
          <h1 className="text-3xl font-bold text-[#002D62]">
            Create your citizen account
          </h1>
          <p className="mt-2 text-gray-600">
            Join the National Integrated Emergency Response System.
          </p>
        </div>

        <Card className="shadow-md">
          <CardHeader className="text-center">
            <h2 className="text-lg font-semibold text-[#002D62]">
              Registration Details
            </h2>
            <p className="mt-1 text-sm text-gray-600">
              Use accurate contact information for report follow-up.
            </p>
          </CardHeader>
          <CardContent>{children}</CardContent>
        </Card>

        <div className="mt-8 text-center text-xs text-gray-500">
          <p>Official NIERS registration portal | 2026</p>
        </div>
      </div>
    </div>
  );
};
