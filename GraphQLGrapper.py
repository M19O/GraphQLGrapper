from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt.event import ActionListener  # Fix here
import json
import re
import os

class BurpExtender(IBurpExtender, IContextMenuFactory, ActionListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("GraphQLGrapper")
        self._callbacks.registerContextMenuFactory(self)
        print("[+] Burp Extension Loaded: GraphQLGrapper")

    def createMenuItems(self, invocation):
        menu_item = JMenuItem("Extract GraphQL Functions", actionPerformed=self.actionPerformed)
        return [menu_item]

    def actionPerformed(self, event):
        http_messages = self._callbacks.getProxyHistory()
        graphql_functions = []

        for message in http_messages:
            request_info = self._helpers.analyzeRequest(message)
            url = request_info.getUrl().toString()
            method = request_info.getMethod()
            body_bytes = message.getRequest()[request_info.getBodyOffset():]
            body = body_bytes.tostring()

            if (method == "POST" or method == "GET") and ("graphql" in url or "query" in body):
                try:
                    json_body = json.loads(body)
                    query = json_body.get("query", "")

                    if query:
                        structured_function = self.extract_graphql_structure(query)
                        if structured_function:
                            graphql_functions.append(structured_function)
                            print("[GraphQL] {} -> {}".format(url, structured_function))

                except Exception:
                    pass  # Ignore non-JSON bodies

        # Save GraphQL structures to a file
        output_path = os.path.expanduser("~/graphql_functions_structure.txt")
        with open(output_path, "w") as f:
            for func in graphql_functions:
                f.write(func + "\n\n")

        print("[+] Extracted GraphQL function structures saved to {}".format(output_path))
        
    def extract_graphql_structure(self, query):
        """Extract structured GraphQL function details."""
        function_structure = []
        lines = query.split("\n")
        function_name = None
        operation_type = None

        for line in lines:
            line = line.strip()

            # Capture query or mutation
            match = re.match(r"^(query|mutation|subscription)\s+(\w+)", line)
            if match:
                operation_type, function_name = match.groups()
                function_structure.append("{} {} (".format(operation_type, function_name))

            # Capture arguments
            elif function_name and "(" in line and "$" in line:
                function_structure.append("    " + line.strip())

            # Capture return fields
            elif function_name and "{" in line:
                function_structure.append("    " + line.strip())

        if function_structure:
            function_structure.append(")")
            return "\n".join(function_structure)
        return None
