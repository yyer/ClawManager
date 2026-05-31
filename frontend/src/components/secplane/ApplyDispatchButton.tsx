import React, { useState } from 'react';
import DispatchPickerModal from './DispatchPickerModal';

// Trigger button + DispatchPickerModal in one. Replaces the prior
// "应用到所有实例" buttons that called dispatchAegisApply() with no args.
// The picker shows a checklist of instances (with running / unhealthy
// badges so the user can see the state), then dispatches to the chosen
// subset or to all.

export interface ApplyDispatchButtonProps {
  // Called with the selected instance ids, or null to dispatch to all.
  onDispatch: (instanceIds: number[] | null) => Promise<unknown> | void;
  busy?: boolean;
  className?: string;
  triggerLabel?: string;
  busyLabel?: string;
  modalTitle?: string;
  modalHint?: string;
  disabled?: boolean;
}

const ApplyDispatchButton: React.FC<ApplyDispatchButtonProps> = ({
  onDispatch,
  busy = false,
  className = 'btn-primary',
  triggerLabel = '应用到实例…',
  busyLabel = '下发中…',
  modalTitle,
  modalHint,
  disabled = false,
}) => {
  const [open, setOpen] = useState(false);

  const handleDispatch = async (ids: number[] | null) => {
    try {
      await onDispatch(ids);
    } finally {
      setOpen(false);
    }
  };

  return (
    <>
      <button
        type="button"
        className={className}
        onClick={() => setOpen(true)}
        disabled={busy || disabled}
      >
        {busy ? busyLabel : triggerLabel}
      </button>
      <DispatchPickerModal
        open={open}
        onClose={() => setOpen(false)}
        onDispatch={handleDispatch}
        dispatching={busy}
        title={modalTitle}
        hint={modalHint}
      />
    </>
  );
};

export default ApplyDispatchButton;
