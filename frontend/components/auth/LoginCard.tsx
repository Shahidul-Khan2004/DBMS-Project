import React from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";

interface LoginCardProps {
  children: React.ReactNode;
}

export const LoginCard: React.FC<LoginCardProps> = ({ children }) => {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-blue-50 to-gray-50 px-4 sm:px-6 lg:px-8">
      <div className="w-full max-w-xl">
        {/* Card */}
        <Card className="shadow-md">
          <CardHeader className="text-center">
            <h1 className="text-3xl font-bold text-gray-900">NIERS</h1>
            <p className="mt-2 text-gray-600">Login</p>
          </CardHeader>
          <CardContent>{children}</CardContent>
        </Card>

        {/* Footer Info */}
        <div className="mt-8 text-center text-xs text-gray-500">
          <p>Secure login • All data encrypted • NIERS © 2026</p>
        </div>
      </div>
    </div>
  );
};
