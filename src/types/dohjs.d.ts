declare module 'dohjs' {
  export interface DnsAnswer {
    name: string;
    type: number;
    class: number;
    ttl: number;
    data: string | Buffer;
  }

  export interface DnsResponse {
    answers: DnsAnswer[];
    questions: DnsQuestion[];
    authorities: DnsAnswer[];
    additionals: DnsAnswer[];
  }

  export interface DnsQuestion {
    name: string;
    type: number;
    class: number;
  }

  export class DohResolver {
    constructor(endpoint: string);
    query(name: string, type: string): Promise<DnsResponse>;
  }

  const doh: {
    DohResolver: typeof DohResolver;
  };

  export default doh;
}
