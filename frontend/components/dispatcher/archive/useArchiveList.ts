"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { ARCHIVE_LIST_LIMIT } from "@/components/dispatcher/archive/archiveConfig";
import { mergeArchiveServiceCases } from "@/components/dispatcher/archive/mergeArchiveServiceCases";
import type {
  ArchiveFinalState,
  ArchivePartialStreamError,
  ArchiveRecordType,
} from "@/components/dispatcher/archive/types";
import { mapOperationsIncidentToActiveListItem } from "@/components/dispatcher/incidents/mapActiveIncidentListItem";
import type { ActiveIncidentListItem } from "@/components/dispatcher/incidents/types";
import { ensureAuthSession } from "@/lib/api";
import { getOperationsIncidents } from "@/lib/operations-intake-triage";
import { listOperationsServiceCases } from "@/lib/service-case-api";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";
import type { OperationsServiceCase } from "@/types/service-case";

type ServiceCaseStreamKey = "closed" | "escalated";

type ServiceCaseStreamState = {
  items: OperationsServiceCase[];
  offset: number;
  total: number;
};

const INITIAL_STREAM: ServiceCaseStreamState = {
  items: [],
  offset: 0,
  total: 0,
};

function incidentStatusForFinalState(finalState: ArchiveFinalState): string {
  return finalState;
}

function serviceCaseStatusForFinalState(finalState: ArchiveFinalState): string {
  return finalState;
}

export function useArchiveList(isReady: boolean) {
  const router = useRouter();
  const [recordType, setRecordType] = useState<ArchiveRecordType>("incidents");
  const [finalState, setFinalState] = useState<ArchiveFinalState>("resolved");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [partialError, setPartialError] = useState<ArchivePartialStreamError>(null);

  const [incidentSourceRows, setIncidentSourceRows] = useState<OperationsIncidentRow[]>([]);
  const [incidentPagination, setIncidentPagination] = useState({
    limit: ARCHIVE_LIST_LIMIT,
    offset: 0,
    total: 0,
  });

  const [serviceCases, setServiceCases] = useState<OperationsServiceCase[]>([]);
  const [serviceCasePagination, setServiceCasePagination] = useState({
    limit: ARCHIVE_LIST_LIMIT,
    offset: 0,
    total: 0,
  });
  const [closedStream, setClosedStream] = useState<ServiceCaseStreamState>(INITIAL_STREAM);
  const [escalatedStream, setEscalatedStream] =
    useState<ServiceCaseStreamState>(INITIAL_STREAM);

  const incidentItems = useMemo(
    () =>
      incidentSourceRows
        .map(mapOperationsIncidentToActiveListItem)
        .filter((item): item is ActiveIncidentListItem => item != null),
    [incidentSourceRows],
  );

  const incidentUuids = useMemo(
    () => incidentItems.map((item) => item.publicUuid),
    [incidentItems],
  );

  const ensureSession = useCallback(async (): Promise<boolean> => {
    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      router.replace("/auth/login");
      return false;
    }
    return true;
  }, [router]);

  const fetchIncidents = useCallback(
    async (append: boolean) => {
      if (!(await ensureSession())) return;

      setIsLoading(true);
      setError(null);
      setPartialError(null);

      const nextOffset = append ? incidentSourceRows.length : 0;

      try {
        const data = await getOperationsIncidents({
          status_code: incidentStatusForFinalState(finalState),
          limit: ARCHIVE_LIST_LIMIT,
          offset: nextOffset,
        });

        const rows = data.incidents ?? [];
        setIncidentSourceRows((current) => (append ? [...current, ...rows] : rows));
        setIncidentPagination(data.pagination);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Archive incidents could not be retrieved. Try again.",
        );
        if (!append) {
          setIncidentSourceRows([]);
        }
      } finally {
        setIsLoading(false);
      }
    },
    [ensureSession, finalState, incidentSourceRows.length],
  );

  const fetchServiceCasesSingle = useCallback(
    async (append: boolean) => {
      if (!(await ensureSession())) return;

      setIsLoading(true);
      setError(null);
      setPartialError(null);

      const nextOffset = append ? serviceCases.length : 0;

      try {
        const data = await listOperationsServiceCases({
          status: serviceCaseStatusForFinalState(finalState),
          limit: ARCHIVE_LIST_LIMIT,
          offset: nextOffset,
        });

        const rows = data.service_cases ?? [];
        setServiceCases((current) => (append ? [...current, ...rows] : rows));
        setServiceCasePagination(data.pagination);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Archive service cases could not be retrieved. Try again.",
        );
        if (!append) {
          setServiceCases([]);
        }
      } finally {
        setIsLoading(false);
      }
    },
    [ensureSession, finalState, serviceCases.length],
  );

  const fetchServiceCasesClosed = useCallback(
    async (append: boolean, retryStream?: ServiceCaseStreamKey) => {
      if (!(await ensureSession())) return;

      setIsLoading(true);
      if (!retryStream) {
        setError(null);
        setPartialError(null);
      }

      const closedFetchOffset = append && !retryStream ? closedStream.offset : 0;
      const escalatedFetchOffset = append && !retryStream ? escalatedStream.offset : 0;

      const shouldFetchClosed = !retryStream || retryStream === "closed";
      const shouldFetchEscalated = !retryStream || retryStream === "escalated";

      const closedPromise = shouldFetchClosed
        ? listOperationsServiceCases({
            status: "closed",
            limit: ARCHIVE_LIST_LIMIT,
            offset: closedFetchOffset,
          })
        : Promise.resolve(null);

      const escalatedPromise = shouldFetchEscalated
        ? listOperationsServiceCases({
            status: "escalated_to_emergency",
            limit: ARCHIVE_LIST_LIMIT,
            offset: escalatedFetchOffset,
          })
        : Promise.resolve(null);

      const [closedResult, escalatedResult] = await Promise.allSettled([
        closedPromise,
        escalatedPromise,
      ]);

      let nextClosed: ServiceCaseStreamState =
        append && !retryStream
          ? { ...closedStream, items: [...closedStream.items] }
          : retryStream === "escalated"
            ? { ...closedStream, items: [...closedStream.items] }
            : { ...INITIAL_STREAM, items: [] };

      let nextEscalated: ServiceCaseStreamState =
        append && !retryStream
          ? { ...escalatedStream, items: [...escalatedStream.items] }
          : retryStream === "closed"
            ? { ...escalatedStream, items: [...escalatedStream.items] }
            : { ...INITIAL_STREAM, items: [] };

      let partial: ArchivePartialStreamError = null;
      let closedFailed = false;
      let escalatedFailed = false;

      if (shouldFetchClosed) {
        if (closedResult.status === "fulfilled" && closedResult.value) {
          const rows = closedResult.value.service_cases ?? [];
          const pagination = closedResult.value.pagination;
          const mergedItems =
            append && !retryStream ? [...nextClosed.items, ...rows] : rows;
          nextClosed = {
            items: mergedItems,
            offset: closedFetchOffset + rows.length,
            total: pagination.total,
          };
        } else if (closedResult.status === "rejected") {
          closedFailed = true;
          const message =
            closedResult.reason instanceof Error
              ? closedResult.reason.message
              : "Closed service cases could not be loaded.";
          if (!retryStream || retryStream === "closed") {
            partial = { stream: "closed", message };
          }
        }
      }

      if (shouldFetchEscalated) {
        if (escalatedResult.status === "fulfilled" && escalatedResult.value) {
          const rows = escalatedResult.value.service_cases ?? [];
          const pagination = escalatedResult.value.pagination;
          const mergedItems =
            append && !retryStream ? [...nextEscalated.items, ...rows] : rows;
          nextEscalated = {
            items: mergedItems,
            offset: escalatedFetchOffset + rows.length,
            total: pagination.total,
          };
        } else if (escalatedResult.status === "rejected") {
          escalatedFailed = true;
          const message =
            escalatedResult.reason instanceof Error
              ? escalatedResult.reason.message
              : "Escalated service cases could not be loaded.";
          if (!retryStream || retryStream === "escalated") {
            partial = { stream: "escalated", message };
          }
        }
      }

      const closedOk = !shouldFetchClosed || !closedFailed;
      const escalatedOk = !shouldFetchEscalated || !escalatedFailed;

      if (!closedOk && !escalatedOk && !append && !retryStream) {
        setError("Archive service cases could not be retrieved. Try again.");
        setServiceCases([]);
        setClosedStream(INITIAL_STREAM);
        setEscalatedStream(INITIAL_STREAM);
        setPartialError(null);
        setIsLoading(false);
        return;
      }

      if (closedOk && escalatedOk) {
        partial = null;
      }

      setClosedStream(nextClosed);
      setEscalatedStream(nextEscalated);
      setServiceCases(mergeArchiveServiceCases(nextClosed.items, nextEscalated.items));
      setPartialError(partial);
      setError(null);
      setIsLoading(false);
    },
    [closedStream, ensureSession, escalatedStream],
  );

  const loadArchive = useCallback(
    async (append: boolean, retryStream?: ServiceCaseStreamKey) => {
      if (recordType === "incidents") {
        await fetchIncidents(append);
        return;
      }

      if (finalState === "closed") {
        await fetchServiceCasesClosed(append, retryStream);
        return;
      }

      await fetchServiceCasesSingle(append);
    },
    [
      fetchIncidents,
      fetchServiceCasesClosed,
      fetchServiceCasesSingle,
      finalState,
      recordType,
    ],
  );

  const refresh = useCallback(() => {
    void loadArchive(false);
  }, [loadArchive]);

  const loadMore = useCallback(() => {
    void loadArchive(true);
  }, [loadArchive]);

  const retryPartialStream = useCallback(
    (stream: ServiceCaseStreamKey) => {
      void fetchServiceCasesClosed(false, stream);
    },
    [fetchServiceCasesClosed],
  );

  const handleRecordTypeChange = useCallback((value: ArchiveRecordType) => {
    setRecordType(value);
    setError(null);
    setPartialError(null);
  }, []);

  const handleFinalStateChange = useCallback((value: ArchiveFinalState) => {
    setFinalState(value);
    setError(null);
    setPartialError(null);
  }, []);

  useEffect(() => {
    if (!isReady) return;
    setIncidentSourceRows([]);
    setServiceCases([]);
    setClosedStream(INITIAL_STREAM);
    setEscalatedStream(INITIAL_STREAM);
    void loadArchive(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- refetch when filters change
  }, [isReady, recordType, finalState]);

  const incidentHasMore =
    incidentSourceRows.length < incidentPagination.total;

  const serviceCaseHasMore =
    recordType === "service_cases" && finalState === "closed"
      ? closedStream.offset < closedStream.total ||
        escalatedStream.offset < escalatedStream.total
      : serviceCases.length < serviceCasePagination.total;

  return {
    recordType,
    finalState,
    setRecordType: handleRecordTypeChange,
    setFinalState: handleFinalStateChange,
    isLoading,
    error,
    partialError,
    incidentSourceRows,
    incidentItems,
    incidentUuids,
    serviceCases,
    refresh,
    loadMore,
    retryPartialStream,
    incidentHasMore,
    serviceCaseHasMore,
  };
}
