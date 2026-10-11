/**
 * The aquarium look tool (0.5.5): `vitna_choose_look`, offered by the guard
 * when VITNA_GUARD_LOOK_TOOL=1. The agent picks one emoji and one colour for
 * how it appears in its owner's VITNA aquarium; the guard answers the call
 * itself through POST /api/aquarium/look with the agent's own key, and never
 * forwards it to the wrapped server. Cosmetic only. The name, description
 * and colours match vigil/lib/aquarium.ts (tests/client-setups or
 * tests/aquarium-tanks check it).
 */

export const LOOK_TOOL_NAME = 'vitna_choose_look';
export const LOOK_TOOL_DESCRIPTION =
  "Choose how you appear in your owner's VITNA aquarium. Cosmetic only: it changes nothing about what you're allowed to do.";
export const LOOK_COLORS = ['teal', 'aqua', 'sky', 'blue', 'violet', 'pink', 'rose', 'coral', 'orange', 'amber', 'lime', 'mint'] as const;

export const LOOK_TOOL = {
  name: LOOK_TOOL_NAME,
  description: LOOK_TOOL_DESCRIPTION,
  inputSchema: {
    type: 'object',
    properties: {
      emoji: { type: 'string', description: 'Exactly one emoji.' },
      color: { type: 'string', enum: [...LOOK_COLORS] },
    },
    required: ['emoji', 'color'],
    additionalProperties: false,
  } as Record<string, unknown>,
};

/** What the agent is told, for each answer from POST /api/aquarium/look. */
export function lookReply(r: { ok: true; value: Record<string, unknown> } | { ok: false; reason: string }): { ok: boolean; text: string } {
  if (r.ok) {
    const look = r.value.look as { emoji?: string; color?: string } | undefined;
    return { ok: true, text: `Your look in the aquarium is now ${look?.emoji ?? ''} ${look?.color ?? ''}. It changes nothing about what you are allowed to do.`.replace(/\s+/g, ' ').trim() };
  }
  const text: Record<string, string> = {
    no_tank: 'Your owner has not made a tank for you yet, so there is no look to set.',
    aquarium_not_enabled: 'The aquarium is not switched on for this account.',
    look_limit: 'Your look can change 5 times a day. Try again tomorrow (UTC).',
    invalid_look: `Choose exactly one emoji, and one of these colours: ${LOOK_COLORS.join(', ')}.`,
    look_conflict: 'Your look changed at the same moment; try again.',
  };
  return { ok: false, text: text[r.reason] ?? `VITNA could not set your look (${r.reason}).` };
}
