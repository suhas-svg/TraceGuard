// Pure cost math. All money is integer micro-dollars; floats never appear.
// Cached tokens bill once at the cached rate, never on top of the full rate.
export interface Price {
  input_price_per_million: number;
  output_price_per_million: number;
  cached_input_price_per_million: number;
}

export function estimateCostMicro(
  inputTokens: number | null,
  outputTokens: number | null,
  cachedTokens: number | null,
  price: Price
): number {
  const input = inputTokens ?? 0;
  const output = outputTokens ?? 0;
  const cached = cachedTokens ?? 0;
  const billableInput = Math.max(0, input - cached);
  return Math.floor(
    (billableInput * price.input_price_per_million +
      output * price.output_price_per_million +
      cached * price.cached_input_price_per_million) / 1_000_000
  );
}

// Worst-case reservation for one call: full expected input plus max_tokens
// of output at the full output rate. The unused remainder is released on settle.
export function maxCallCostMicro(
  expectedInputTokens: number,
  maxOutputTokens: number,
  price: Price
): number {
  return estimateCostMicro(expectedInputTokens, maxOutputTokens, 0, price);
}
