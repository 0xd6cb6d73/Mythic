import React from 'react';
import {gql, useSubscription} from '@apollo/client';

const CryptoProviderContext = React.createContext({providers: [], loading: false, error: null});

export const cryptoProvidersSubscription = gql`
subscription PayloadCryptoProviders {
    consuming_container(where: {type: {_eq: "crypto"}, deleted: {_eq: false}}, order_by: {name: asc}) {
        id
        name
        container_running
        crypto_capabilities
    }
}
`;

export function CryptoProviderDiscovery({children}){
    const {data, loading, error} = useSubscription(cryptoProvidersSubscription);
    const value = React.useMemo(() => ({
        providers: data?.consuming_container || [], loading, error,
    }), [data, loading, error]);
    return <CryptoProviderContext.Provider value={value}>{children}</CryptoProviderContext.Provider>;
}

export const useCryptoProviders = () => React.useContext(CryptoProviderContext);
