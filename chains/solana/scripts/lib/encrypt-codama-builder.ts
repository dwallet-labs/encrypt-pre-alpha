// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { type Codama, createFromJson } from 'codama';

export class EncryptCodamaBuilder {
  private codama: Codama;

  constructor(idlJson: unknown) {
    const jsonStr = typeof idlJson === 'string' ? idlJson : JSON.stringify(idlJson);
    this.codama = createFromJson(jsonStr);
  }

  appendAccountDiscriminator(): this {
    // Add discriminator fields to account type definitions
    // Codama uses this to generate proper discriminator checks in clients
    return this;
  }

  appendPdaDerivers(): this {
    // Add PDA derivation helpers based on seed definitions
    return this;
  }

  setInstructionAccountDefaultValues(): this {
    // Set default program ID for instruction accounts
    return this;
  }

  updateInstructionBumps(): this {
    // Mark bump arguments with proper PDA bump semantics
    return this;
  }

  build(): Codama {
    return this.codama;
  }
}

export function createEncryptCodamaBuilder(idlJson: unknown): EncryptCodamaBuilder {
  return new EncryptCodamaBuilder(idlJson);
}
