declare module "bs58" {
  const codec: {
    encode(value: Uint8Array): string;
    decode(value: string): Uint8Array;
  };
  export default codec;
}
