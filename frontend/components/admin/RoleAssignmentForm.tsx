"use client";

import { useState } from "react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";

interface User {
  id: string;
  email: string;
  full_name: string;
  phone_number: string;
}

export const RoleAssignmentForm: React.FC = () => {
  const [userId, setUserId] = useState("");
  const [user, setUser] = useState<User | null>(null);
  const [selectedRole, setSelectedRole] = useState("dispatcher");
  const [isSearching, setIsSearching] = useState(false);
  const [isAssigning, setIsAssigning] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const handleSearch = async () => {
    if (!userId.trim()) {
      setMessage({ type: "error", text: "Please enter a user ID" });
      return;
    }

    setIsSearching(true);
    setMessage(null);

    try {
      const accessToken = localStorage.getItem("accessToken");
      const response = await fetch(`http://localhost:8080/users/${userId}`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        throw new Error("User not found");
      }

      const data = await response.json();
      setUser(data.user);
      setMessage(null);
    } catch (error) {
      setMessage({
        type: "error",
        text: error instanceof Error ? error.message : "Failed to fetch user",
      });
      setUser(null);
    } finally {
      setIsSearching(false);
    }
  };

  const handleAssignRole = async () => {
    if (!user) {
      setMessage({ type: "error", text: "No user selected" });
      return;
    }

    setIsAssigning(true);
    setMessage(null);

    try {
      const accessToken = localStorage.getItem("accessToken");
      const response = await fetch(
        `http://localhost:8080/users/${user.id}/roles`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
          },
          body: JSON.stringify({
            roleCode: selectedRole,
          }),
        },
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error?.message || "Failed to assign role");
      }

      setMessage({
        type: "success",
        text: `Role "${selectedRole}" assigned to ${user.full_name} successfully`,
      });
      setUser(null);
      setUserId("");
      setSelectedRole("dispatcher");
    } catch (error) {
      setMessage({
        type: "error",
        text: error instanceof Error ? error.message : "Failed to assign role",
      });
    } finally {
      setIsAssigning(false);
    }
  };

  return (
    <Card className="shadow-md">
      <CardHeader>
        <h2 className="text-lg font-semibold text-gray-900">
          Assign Dispatcher Role
        </h2>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Search User */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Search User by ID
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="Enter user UUID"
                className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
              <Button
                onClick={handleSearch}
                isLoading={isSearching}
                disabled={isSearching || isAssigning}
              >
                Search
              </Button>
            </div>
          </div>

          {/* User Info */}
          {user && (
            <div className="rounded-lg bg-blue-50 p-4">
              <p className="text-sm">
                <span className="font-medium text-gray-700">Name:</span>{" "}
                <span className="text-gray-600">{user.full_name}</span>
              </p>
              <p className="mt-2 text-sm">
                <span className="font-medium text-gray-700">Email:</span>{" "}
                <span className="text-gray-600">{user.email}</span>
              </p>
              <p className="mt-2 text-sm">
                <span className="font-medium text-gray-700">Phone:</span>{" "}
                <span className="text-gray-600">{user.phone_number}</span>
              </p>
            </div>
          )}

          {/* Role Selection */}
          {user && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Select Role
              </label>
              <select
                value={selectedRole}
                onChange={(e) => setSelectedRole(e.target.value)}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="citizen">Citizen</option>
                <option value="dispatcher">Dispatcher</option>
                <option value="agency_representative">
                  Agency Representative
                </option>
              </select>
            </div>
          )}

          {/* Assign Button */}
          {user && (
            <Button
              onClick={handleAssignRole}
              isLoading={isAssigning}
              disabled={isAssigning}
              fullWidth
              className="bg-green-600 hover:bg-green-700"
            >
              Assign Role
            </Button>
          )}

          {/* Messages */}
          {message && (
            <div
              className={`rounded-lg p-3 text-sm ${
                message.type === "success"
                  ? "bg-green-50 text-green-700"
                  : "bg-red-50 text-red-700"
              }`}
            >
              {message.text}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
