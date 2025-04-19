import { useState, useEffect } from 'react';
import {
    Box,
    Button,
    CircularProgress
} from '@mui/material';
import axios from 'axios';

// React component for HubSpot Integration
export const HubspotIntegration = ({ user, org, integrationParams, setIntegrationParams }) => {
    const [isConnected, setIsConnected] = useState(false);       // Tracks connection status
    const [isConnecting, setIsConnecting] = useState(false);     // Tracks loading state while connecting

    /**
     * @function handleConnectClick
     * @description Called when the user clicks the "Connect to HubSpot" button.
     * It sends a request to the backend to get the HubSpot OAuth authorization URL,
     * then opens it in a popup window so the user can log in and authorize access.
     * It also starts polling to detect when the popup is closed.
     *
     * @params none (uses user and org from component scope)
     *
     * @returns void - but internally:
     * - Opens HubSpot OAuth login in a new window
     * - Starts polling to detect window closure
     * - On window close, calls handleWindowClosed to fetch credentials
     * - Temporarily disables the button via isConnecting state
     */
    const handleConnectClick = async () => {
        try {
            setIsConnecting(true);

            // Create form data with user/org info to send to backend
            const formData = new FormData();
            formData.append('user_id', user);
            formData.append('org_id', org);

            // Call backend to get the HubSpot authorization URL
            const response = await axios.post(`http://localhost:8000/integrations/hubspot/authorize`, formData);
            const authURL = response?.data;

            // Open the HubSpot OAuth login screen in a new popup window
            const newWindow = window.open(authURL, 'HubSpot Authorization', 'width=600, height=600');

            // Poll the popup to check when it's closed
            const pollTimer = window.setInterval(() => {
                if (newWindow?.closed !== false) {
                    window.clearInterval(pollTimer);
                    handleWindowClosed(); // Fetch credentials once popup is closed
                }
            }, 200);
        } catch (e) {
            setIsConnecting(false);
            alert(e?.response?.data?.detail);
        }
    }

    /**
     * @function handleWindowClosed
     * @description This function is triggered after the HubSpot OAuth popup is closed.
     * It sends a POST request to the backend to retrieve stored credentials (access token)
     * that were saved after successful OAuth authorization.
     *
     * @params none (uses user and org from component scope)
     *
     * @returns void - but internally:
     * - Updates state to show connection success
     * - Calls setIntegrationParams to save credentials and integration type
     * - Enables the next UI step: "Load Data"
     */
    const handleWindowClosed = async () => {
        try {
            const formData = new FormData();
            formData.append('user_id', user);
            formData.append('org_id', org);

            // Get stored HubSpot credentials from backend (from Redis)
            const response = await axios.post(`http://localhost:8000/integrations/hubspot/credentials`, formData);
            const credentials = response.data;

            if (credentials) {
                setIsConnecting(false);
                setIsConnected(true); // Mark as connected
                // Save credentials and integration type to global state
                setIntegrationParams(prev => ({ ...prev, credentials: credentials, type: 'hubspot' }));
            }
        } catch (e) {
            setIsConnecting(false);
            alert(e?.response?.data?.detail);
        }
    }

    // Runs on component mount to check if we're already connected
    useEffect(() => {
        setIsConnected(integrationParams?.credentials ? true : false);
    }, []);

    return (
        <>
            <Box sx={{ mt: 2 }}>
                Parameters
                <Box display='flex' alignItems='center' justifyContent='center' sx={{ mt: 2 }}>
                    <Button
                        variant='contained'
                        onClick={isConnected ? () => {} : handleConnectClick}
                        color={isConnected ? 'success' : 'primary'}
                        disabled={isConnecting}
                        style={{
                            pointerEvents: isConnected ? 'none' : 'auto',
                            cursor: isConnected ? 'default' : 'pointer',
                            opacity: isConnected ? 1 : undefined
                        }}
                    >
                        {
                            isConnected
                                ? 'HubSpot Connected'
                                : isConnecting
                                    ? <CircularProgress size={20} />
                                    : 'Connect to HubSpot'
                        }
                    </Button>
                </Box>
            </Box>
        </>
    );
};
