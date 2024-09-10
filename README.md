# **D4 Unique Items Viewer**

**Welcome, Hero!** This is your gateway to exploring the unique items of Diablo 4. Harness the power of the API to view and manage your precious loot.

---

## **⚔️ Features**

- **View Unique Items**: Browse through the legendary items of Diablo 4.
- **Filter by Class**: Refine your search based on your character's class.
- **Image Display**: See the visual representation of each item.

---

## **🔧 Setup**

1. **Install Dependencies**:
   ```bash
   pip install Flask Flask-Caching requests
   ```
2. **Run the APP**:
    ```bash
    python app.py
    ```
3. Access the page at http://localhost:5000.

## **🛡️ Routes**

- **/:** List of unique items with filtering options.
- **/image:** Fetch the image URL for a specific item.

## **⚠️ Troubleshooting**

- **Error 429:** API rate limit exceeded. Retry after some time.
- **Data Issues:** Ensure **uniques_data.json** is properly updated.

## **📝 License**

- MIT License. See LICENSE for details.

<hr>
<div align="center">
<b>May your journey be prosperous and your loot <font color='orange'>legendary!</font></b>

</div> 