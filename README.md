### HOW TO RUN THE GENERATE SOLUTION DETAILS SCRIPT:

$ python .\gen_solution_report.py .\T8-2024\DMZ.csv .\T8-2024\DMZ.xml

so the output file should be generated at .\DMZ_Solution_Details.xlsx

-----------

### HOW TO RUN THE GENERATE VULN DETAILS SCRIPT:

$ python .\gen_vuln_report.py .\T8-2024\DMZ.csv .\T8-2024\DMZ.xml

so the output file should be generated at .\DMZ_Vuln_Details.xlsx

.csv file should be exported from Rapid 7 InsightVM (or Nexpose) as "Basic Vulnerabilities Check Result" template.
.xml file should be exported from Rapid 7 InsightVM (or Nexpose) as "XML Export 2.0" template.