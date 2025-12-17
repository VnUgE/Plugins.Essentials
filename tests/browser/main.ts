import { createApiConfig } from "@vnuge/vnlib.browser";
import Axios from "axios";

export const vnlib = createApiConfig({
    account: {
        endpointUrl: '/api/account'
    },
    axios: {
        instance: Axios.create({
            baseURL:"/test",
            withCredentials: true
        }),
    },
    session: { }
    // storage auto-detected: uses wrapped localStorage in browser/jsdom
})