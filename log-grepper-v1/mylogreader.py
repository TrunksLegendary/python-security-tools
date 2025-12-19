"""simple log search tool"""

def main():
    """simple log search tool"""

    filepath = "sample_logs/app.log"
    linesread = 0
    linesfound = 0
    searchword = input ("enter wordto search for :")
    with open(filepath, "r", encoding="utf-8") as file:
        for line in file:
            linesread += 1
            if searchword in line:
                linesfound +=1
    print (f"Total Lines read :{linesread}")
    print (f"lines found containing {searchword} : {linesfound}")


if __name__ == "__main__":
    main()
# End of file
