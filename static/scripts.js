// Function to handle the search
function handleSearch() {
    // Get the search input value
    let searchQuery = document.getElementById("search-query-input").value;

    // Trim whitespace (remove leading and trailing spaces)
    searchQuery = searchQuery.trim();

    // Encode the search query for the URL (this will replace spaces with %20 instead of +)
    let encodedQuery = encodeURIComponent(searchQuery);

    // Perform the search or display the no-results message
    if (encodedQuery.length === 0) {
        displayNoResults("Nothing to search");
    } else {
        // Update the URL without trailing +
        performSearch(encodedQuery);
    }
}

// Example function to show no results
function displayNoResults(query) {
    document.getElementById("search-query").textContent = query;
}

// Simulate the search process (replace with actual search logic)
function performSearch(query) {
    // Update the URL for the search query (removing any trailing + or spaces)
    let searchUrl = `/search?q=${query}`;

    // Simulate updating the URL (you can also redirect to the search results page here)
    console.log("Updated search URL:", searchUrl);

    // Perform any other actions based on the query
    displayNoResults(query);
}