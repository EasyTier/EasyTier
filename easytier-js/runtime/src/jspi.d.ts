declare namespace WebAssembly {
  type JspiCallable = (...parameters: never[]) => unknown;

  class Suspending extends Function {
    constructor(
      callable: (...parameters: never[]) => Promise<number>,
    );
  }

  function promising<T extends JspiCallable>(
    callable: T,
  ): (...parameters: Parameters<T>) => Promise<Awaited<ReturnType<T>>>;
}
