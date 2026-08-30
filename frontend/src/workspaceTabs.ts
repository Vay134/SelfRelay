export type WorkspaceView = 'account' | 'transfers';

export type WorkspaceTab = {
    id: WorkspaceView;
    label: string;
};

export const WORKSPACE_VIEWS: WorkspaceTab[] = [
    { id: 'account', label: 'Account' },
    { id: 'transfers', label: 'Transfer devices' },
];

export function nextWorkspaceView(view: WorkspaceView, key: string): WorkspaceView | null {
    const index = WORKSPACE_VIEWS.findIndex((item) => item.id === view);
    if (index === -1) {
        return null;
    }
    if (key === 'Home') {
        return WORKSPACE_VIEWS[0].id;
    }
    if (key === 'End') {
        return WORKSPACE_VIEWS[WORKSPACE_VIEWS.length - 1].id;
    }
    if (key !== 'ArrowRight' && key !== 'ArrowLeft') {
        return null;
    }
    const direction = key === 'ArrowRight' ? 1 : -1;
    return WORKSPACE_VIEWS[(index + direction + WORKSPACE_VIEWS.length) % WORKSPACE_VIEWS.length]
        .id;
}
