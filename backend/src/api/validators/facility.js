import { z } from "zod";
import validate from "./validator.js";
import { locationObjectSchema } from "./validationSchemas.js";

export const validateCreateFacility = validate(
  "createFacility",
  z.object({
    facilityTypeCode: z.string().min(1),
    name: z.string().min(1).max(180),
    facilityCode: z.string().max(80).optional(),
    location: locationObjectSchema,
  }),
);

export const validateFacilityCapabilities = validate(
  "facilityCapabilities",
  z.object({
    capabilityCodes: z.array(z.string().min(1)).min(1),
  }),
);

export const validateFacilityDefaultCapacities = validate(
  "facilityDefaultCapacities",
  z.object({
    capacities: z
      .array(
        z.object({
          capacityType: z.enum(["shelter_people", "hospital_beds", "emergency_beds"]),
          totalCapacity: z.number().int().positive(),
        }),
      )
      .min(1),
  }),
);
