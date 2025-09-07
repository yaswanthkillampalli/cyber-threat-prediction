// src/components/DateRangeModal.jsx

import { useState, useEffect } from 'react';
import { Modal, Button } from 'react-bootstrap';
import DatePicker from 'react-datepicker';
import "react-datepicker/dist/react-datepicker.css"; // Styles for the date picker

export default function DateRangeModal({ show, onHide, onApply, minDate, maxDate }) {
  // Internal state to manage dates before applying
  const [startDate, setStartDate] = useState(new Date());
  const [endDate, setEndDate] = useState(new Date());

  // Update internal dates when the modal is shown
  useEffect(() => {
    setStartDate(minDate || new Date());
    setEndDate(maxDate || new Date());
  }, [show, minDate, maxDate]);

  const handleApplyClick = () => {
    onApply(startDate, endDate);
    onHide();
  };

  return (
    <Modal show={show} onHide={onHide} centered>
      <Modal.Header closeButton>
        <Modal.Title>Select Custom Date Range</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <p className="text-muted">
          Data available from {minDate ? minDate.toLocaleDateString() : '...'} to {maxDate ? maxDate.toLocaleDateString() : '...'}.
        </p>
        <div className="d-flex justify-content-around">
          <div className="d-flex flex-column">
            <strong>Start Date</strong>
            <DatePicker
              selected={startDate}
              onChange={(date) => setStartDate(date)}
              selectsStart
              startDate={startDate}
              endDate={endDate}
              minDate={minDate}
              maxDate={maxDate}
              showTimeSelect
              dateFormat="Pp"
            />
          </div>
          <div className="d-flex flex-column">
            <strong>End Date</strong>
            <DatePicker
              selected={endDate}
              onChange={(date) => setEndDate(date)}
              selectsEnd
              startDate={startDate}
              endDate={endDate}
              minDate={minDate}
              maxDate={maxDate}
              showTimeSelect
              dateFormat="Pp"
            />
          </div>
        </div>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Cancel
        </Button>
        <Button variant="primary" onClick={handleApplyClick}>
          Get Analysis
        </Button>
      </Modal.Footer>
    </Modal>
  );
}