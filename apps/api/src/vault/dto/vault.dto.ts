import { IsInt, IsObject, Min } from 'class-validator';

export class PutVaultDto {
  @IsInt()
  @Min(0)
  expectedRevision!: number;

  @IsObject()
  envelope!: Record<string, unknown>;
}
