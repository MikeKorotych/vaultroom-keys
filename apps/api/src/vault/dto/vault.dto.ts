import { IsBoolean, IsInt, IsObject, IsOptional, Min } from 'class-validator';

export class PutVaultDto {
  @IsInt()
  @Min(0)
  expectedRevision!: number;

  @IsObject()
  envelope!: Record<string, unknown>;

  /** Set after a rekey: earlier envelopes open with the old secrets, so none are kept. */
  @IsOptional()
  @IsBoolean()
  resetHistory?: boolean;
}
