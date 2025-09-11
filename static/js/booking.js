// static/js/booking.js

document.addEventListener('DOMContentLoaded', function() {
    const startDateInput = document.getElementById('startDate');
    const endDateInput = document.getElementById('endDate');

    // Get today's date in YYYY-MM-DD format
    const today = new Date();
    const year = today.getFullYear();
    const month = String(today.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
    const day = String(today.getDate()).padStart(2, '0');
    const todayFormatted = `${year}-${month}-${day}`;

    // Set the minimum date for both start and end date inputs to today
    startDateInput.setAttribute('min', todayFormatted);
    endDateInput.setAttribute('min', todayFormatted);

    // Add an event listener to ensure end date is not before start date
    // and allows start and end on the same day.
    startDateInput.addEventListener('change', function() {
        if (this.value) {
            // Set the minimum date for the end date to be the selected start date
            // This implicitly allows the end date to be the same as the start date.
            endDateInput.setAttribute('min', this.value);

            // If the current end date is *strictly before* the new start date, clear it.
            // If it's the same day, it's valid.
            if (endDateInput.value && endDateInput.value < this.value) {
                endDateInput.value = '';
            }
        } else {
            // If start date is cleared, reset end date's min to today
            endDateInput.setAttribute('min', todayFormatted);
            // Optionally clear the end date if the start date is cleared
            // endDateInput.value = '';
        }
    });

    // Optional: Add an event listener to ensure start date isn't set after end date
    // This adds more robustness but can sometimes be overly strict for initial selection.
    // endDateInput.addEventListener('change', function() {
    //     if (this.value && startDateInput.value && startDateInput.value > this.value) {
    //         startDateInput.value = ''; // Clear start date if it's after end date
    //     }
    // });
});