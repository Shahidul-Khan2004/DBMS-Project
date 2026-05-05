import React from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";

interface RegistrationCardProps {
  children: React.ReactNode;
}

export const RegistrationCard: React.FC<RegistrationCardProps> = ({
  children,
}) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-gray-50 py-8 px-4 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-xl">
        {/* Header */}
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold text-gray-900">
            NIERS Registration
          </h1>
          <p className="mt-2 text-gray-600">
            Join the National Integrated Emergency Response System
          </p>
        </div>

        {/* Card */}
        <Card className="shadow-md">
          <CardHeader className="text-center">
            <h2 className="text-lg font-semibold text-gray-900">
              Create Your Account
            </h2>
            <p className="mt-1 text-sm text-gray-500">
              Fill in the details below to get started
            </p>
          </CardHeader>
          <CardContent>{children}</CardContent>
        </Card>

        {/* Footer Info */}
        <div className="mt-8 text-center text-xs text-gray-500">
          <p>Secure registration • All data encrypted • NIERS © 2026</p>
        </div>
      </div>
    </div>
  );
};
