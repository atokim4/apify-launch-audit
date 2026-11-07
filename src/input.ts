import { z } from 'zod';

export const InputSchema = z.object({
  urls: z
    .array(z.string().trim().min(1))
    .min(1, 'Add at least one URL')
    .max(100, 'At most 100 URLs per run')
    .transform((urls) => [...new Set(urls)]),
  maxBundles: z.number().int().min(1).max(100).default(20),
  timeoutSecs: z.number().int().min(5).max(60).default(15),
});

export type Input = z.infer<typeof InputSchema>;

export function parseInput(raw: unknown): Input {
  const result = InputSchema.safeParse(raw ?? {});
  if (!result.success) {
    const issues = result.error.issues.map((i) => `${i.path.join('.') || 'input'}: ${i.message}`);
    throw new Error(`Invalid input. ${issues.join('; ')}`);
  }
  return result.data;
}
