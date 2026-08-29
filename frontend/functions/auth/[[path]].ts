interface GatewayEnvironment { UPSTREAM_ORIGIN: string }

export const onRequest = async (context: { request: Request; env: GatewayEnvironment }): Promise<Response> => {
    const upstream = new URL(context.request.url);
    const origin = new URL(context.env.UPSTREAM_ORIGIN);
    upstream.protocol = origin.protocol;
    upstream.host = origin.host;
    return fetch(new Request(upstream, context.request));
};
