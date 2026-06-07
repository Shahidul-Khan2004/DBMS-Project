"use client";

import { useRouter } from "next/navigation";
import { Gateway999IntakePanel } from "@/components/dispatcher/gateway-999/Gateway999IntakePanel";
import { Gateway999LocationPanel } from "@/components/dispatcher/gateway-999/Gateway999LocationPanel";
import { Gateway999SuccessHandoff } from "@/components/dispatcher/gateway-999/Gateway999SuccessHandoff";
import { useGateway999Intake } from "@/components/dispatcher/gateway-999/useGateway999Intake";

export function Gateway999Workspace() {
  const router = useRouter();
  const {
    form,
    updateForm,
    handleSelectRoute,
    handleLocationChange,
    handleAddressTextChange,
    handlePlaceNameChange,
    handleSubmit,
    resetForm,
    isSubmitting,
    submitError,
    showValidation,
    handoff,
    canSubmit,
    submitLabel,
    incidents,
    incidentsLoading,
    incidentsError,
    loadIncidents,
    selectedDisasterPublicUuid,
    setSelectedDisasterPublicUuid,
  } = useGateway999Intake();

  const handleCancel = () => {
    router.push("/dashboard/dispatcher");
  };

  const handleOpenDetail = () => {
    if (handoff?.detailHref) {
      router.push(handoff.detailHref);
    }
  };

  return (
    <div className="flex w-full min-h-0 flex-1 flex-col gap-2.5 pb-2 pt-0 lg:min-h-0 lg:flex-1 lg:overflow-hidden lg:pb-2 lg:pt-0">
      {handoff ? (
        <>
          <header className="shrink-0 space-y-0.5">
            <h1 className="text-xl font-semibold text-slate-900">Start 999 Intake</h1>
            <p className="text-sm text-slate-600">
              Record a live emergency call and route it immediately.
            </p>
          </header>
          <div className="min-h-0 flex-1 overflow-y-auto rounded-2xl border border-slate-200/90 bg-white p-4 shadow-sm sm:p-5">
            <Gateway999SuccessHandoff
              handoff={handoff}
              onOpenDetail={handleOpenDetail}
              onStartAnother={resetForm}
            />
          </div>
        </>
      ) : (
        <form
          onSubmit={handleSubmit}
          noValidate
          className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:min-h-0 lg:grid-cols-[minmax(0,54fr)_minmax(0,46fr)] lg:items-stretch lg:overflow-hidden"
        >
          <div className="flex min-h-0 flex-col gap-3">
            <header className="shrink-0 space-y-0.5">
              <h1 className="text-xl font-semibold text-slate-900">Start 999 Intake</h1>
              <p className="text-sm text-slate-600">
                Record a live emergency call and route it immediately.
              </p>
            </header>
            <div className="flex min-h-0 flex-1 flex-col">
              <Gateway999IntakePanel
                form={form}
                routeMode={form.routeMode}
                isSubmitting={isSubmitting}
                submitError={submitError}
                showValidation={showValidation}
                canSubmit={canSubmit}
                submitLabel={submitLabel}
                incidents={incidents}
                incidentsLoading={incidentsLoading}
                incidentsError={incidentsError}
                onFormChange={updateForm}
                onSelectRoute={handleSelectRoute}
                onRetryIncidents={() => void loadIncidents()}
                onCancel={handleCancel}
                selectedDisasterPublicUuid={selectedDisasterPublicUuid}
                onDisasterChange={setSelectedDisasterPublicUuid}
              />
            </div>
          </div>

          <div className="flex min-h-0 flex-col lg:h-full">
            <Gateway999LocationPanel
              selectedLocation={form.selectedLocation}
              addressText={form.addressText}
              placeName={form.placeName}
              isSubmitting={isSubmitting}
              showValidation={showValidation}
              onLocationChange={handleLocationChange}
              onAddressTextChange={handleAddressTextChange}
              onPlaceNameChange={handlePlaceNameChange}
            />
          </div>
        </form>
      )}
    </div>
  );
}
